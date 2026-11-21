using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace OsirisSuite
{
    internal static class OsirisLauncher
    {
        private static bool IsServerAlive(int port)
        {
            try
            {
                HttpWebRequest req = (HttpWebRequest)WebRequest.Create("http://127.0.0.1:" + port + "/api/status");
                req.Method = "GET";
                req.Proxy = null;
                req.Timeout = 500;
                req.ReadWriteTimeout = 500;
                using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
                {
                    return (int)resp.StatusCode == 200;
                }
            }
            catch
            {
                return false;
            }
        }

        private static string FindPythonExecutable(string baseDir)
        {
            string[] bundled = new string[] {
                Path.Combine(baseDir, "_osiris_runtime", "pythonw.exe"),
                Path.Combine(baseDir, "_osiris_runtime", "python.exe")
            };
            foreach (string bp in bundled)
            {
                try
                {
                    if (File.Exists(bp)) return bp;
                }
                catch { }
            }
            string[] candidates = new string[] { "pythonw.exe", "python.exe", "py.exe" };
            string pathEnv = Environment.GetEnvironmentVariable("PATH") ?? "";
            foreach (string dir in pathEnv.Split(Path.PathSeparator))
            {
                if (string.IsNullOrWhiteSpace(dir)) continue;
                foreach (string exe in candidates)
                {
                    try
                    {
                        string full = Path.Combine(dir.Trim(), exe);
                        if (File.Exists(full)) return full;
                    }
                    catch { }
                }
            }
            string localPy = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "Python");
            if (Directory.Exists(localPy))
            {
                try
                {
                    foreach (string sub in Directory.GetDirectories(localPy, "Python*"))
                    {
                        foreach (string exe in new string[] { "pythonw.exe", "python.exe" })
                        {
                            string full = Path.Combine(sub, exe);
                            if (File.Exists(full)) return full;
                        }
                    }
                }
                catch { }
            }
            return null;
        }

        private static string EncodePsCommand(string script)
        {
            return Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        }

        private static bool InstallShortcuts(string exePath, string baseDir, out string errorMsg)
        {
            errorMsg = "";
            try
            {
                string desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
                string startDir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "Microsoft", "Windows", "Start Menu", "Programs", "Osiris Suite");
                Directory.CreateDirectory(startDir);

                string delIcoFile = Path.Combine(baseDir, "FILES INDEXATION_DELETER", "osiris_deleter.ico");
                string delIconLoc = File.Exists(delIcoFile) ? delIcoFile : (exePath + ",0");

                string psScript =
                    "$ws = New-Object -ComObject WScript.Shell; " +
                    "$dests = ($env:OSIRIS_DESTS -split '\\|') | Where-Object { $_ -and (Test-Path -LiteralPath $_) }; " +
                    "$specs = @(" +
                    "  @('Osiris Files Indexer.lnk', '', 'Osiris Portable Files Indexer (Read-Only)', $env:OSIRIS_ICO)," +
                    "  @('Osiris Files Checker & Deleter.lnk', '--deleter', 'Osiris Corrupted Files Checker & Quarantine Deleter', $env:OSIRIS_DEL_ICO)" +
                    "); " +
                    "foreach ($d in $dests) { foreach ($sp in $specs) { " +
                    "  $s = $ws.CreateShortcut((Join-Path $d $sp[0])); " +
                    "  $s.TargetPath = $env:OSIRIS_EXE; " +
                    "  $s.Arguments = $sp[1]; " +
                    "  $s.WorkingDirectory = $env:OSIRIS_BASE; " +
                    "  $s.Description = $sp[2]; " +
                    "  $s.IconLocation = $sp[3]; " +
                    "  $s.Save(); " +
                    "} }";

                ProcessStartInfo psi = new ProcessStartInfo(
                    "powershell.exe",
                    "-NoProfile -ExecutionPolicy Bypass -EncodedCommand " + EncodePsCommand(psScript));
                psi.EnvironmentVariables["OSIRIS_DESTS"] = desktop + "|" + startDir;
                psi.EnvironmentVariables["OSIRIS_EXE"] = exePath;
                psi.EnvironmentVariables["OSIRIS_BASE"] = baseDir;
                psi.EnvironmentVariables["OSIRIS_ICO"] = exePath + ",0";
                psi.EnvironmentVariables["OSIRIS_DEL_ICO"] = delIconLoc;
                psi.CreateNoWindow = true;
                psi.UseShellExecute = false;
                psi.RedirectStandardError = true;
                using (Process p = Process.Start(psi))
                {
                    if (p == null)
                    {
                        errorMsg = "Failed to launch PowerShell.";
                        return false;
                    }
                    string err = p.StandardError.ReadToEnd();
                    if (!p.WaitForExit(15000))
                    {
                        try { p.Kill(); } catch { }
                        errorMsg = "Shortcut creation timed out.";
                        return false;
                    }
                    if (p.ExitCode != 0)
                    {
                        errorMsg = err;
                        return false;
                    }
                }
                return true;
            }
            catch (Exception ex)
            {
                errorMsg = ex.Message;
                return false;
            }
        }

        private static void RunPowerShellSnapshotFallback(string driveRoot, string baseDir)
        {
            string psScript =
                "$ErrorActionPreference='SilentlyContinue'; " +
                "$drv=$env:FIS_DRV; $base=$env:FIS_BASE; " +
                "$root=$drv.TrimEnd('\\','/') + '/'; $rootWin=$drv.TrimEnd('\\','/') + '\\'; " +
                "$skip=@('$recycle.bin','$winreagent','$sysreset','$windows.~bt','$windows.~ws','system volume information','windows','winnt','program files','program files (x86)','programdata','recovery','config.msi','documents and settings','perflogs','msocache','onedrivetemp','system32','syswow64','winsxs','boot','efi','appdata','application data','local settings','cookies','nethood','printhood','recent','sendto','start menu','templates','all users','default','default user','temp','tmp','cache','caches','gpucache','code cache','shadercache','crashpad','thumbnails','.thumbnails','node_modules','bower_components','vendor','.git','.hg','.svn','__pycache__','.venv','venv','env','.tox','.pytest_cache','.mypy_cache','.ruff_cache','site-packages','dist-packages','.gemini','.cache','.npm','.yarn','.pnpm-store','.cargo','.rustup','.vscode','.cursor','.idea','.gradle','.m2','.android','.lmstudio','.ollama','.nuget','_osiris_quarantine','_osiris_runtime'); " +
                "$skipFiles=@('pagefile.sys','hiberfil.sys','swapfile.sys','dumpstack.log','dumpstack.log.tmp','thumbs.db','ehthumbs.db','ehthumbs_vista.db','desktop.ini','iconcache.db','.ds_store','ntuser.dat','ntuser.dat.log1','ntuser.dat.log2','ntuser.ini','usrclass.dat','usrclass.dat.log1','usrclass.dat.log2'); " +
                "$catMap=@{}; @('.mp4','.mkv','.avi','.mov','.webm','.wmv','.flv','.m4v','.mpg','.mpeg','.3gp','.ogv') | ForEach-Object { $catMap[$_]='video' }; @('.mp3','.wav','.flac','.aac','.ogg','.m4a','.wma','.opus','.mid','.midi') | ForEach-Object { $catMap[$_]='audio' }; @('.jpg','.jpeg','.png','.gif','.webp','.svg','.bmp','.ico','.tif','.tiff','.avif') | ForEach-Object { $catMap[$_]='image' }; $catMap['.pdf']='pdf'; @('.doc','.docx','.xls','.xlsx','.ppt','.pptx','.odt','.ods','.odp','.txt','.md','.csv','.rtf','.log') | ForEach-Object { $catMap[$_]='doc' }; @('.py','.js','.ts','.jsx','.tsx','.html','.htm','.css','.scss','.json','.xml','.yaml','.yml','.c','.cpp','.h','.hpp','.ino','.java','.kt','.go','.rs','.php','.sh','.bat','.ps1','.sql','.vbs') | ForEach-Object { $catMap[$_]='code' }; @('.zip','.rar','.7z','.tar','.gz','.bz2','.xz','.iso') | ForEach-Object { $catMap[$_]='archive' }; @('.exe','.msi','.apk','.dll','.appx','.sys') | ForEach-Object { $catMap[$_]='exe' }; " +
                "$files=[System.Collections.Generic.List[object]]::new(); $tot=[int64]0; $ep=[datetime]'1970-01-01T00:00:00Z'; " +
                "$st=[System.Collections.Generic.Stack[string]]::new(); $st.Push($rootWin); " +
                "while($st.Count -gt 0){ $d=$st.Pop(); try{ foreach($s in [System.IO.Directory]::GetDirectories($d)){ $dn=[System.IO.Path]::GetFileName($s); $dl=$dn.ToLowerInvariant(); if(($skip -notcontains $dl) -and (-not $dn.StartsWith('$')) -and (-not $dn.StartsWith('.'))){ $st.Push($s) } }; foreach($fp in [System.IO.Directory]::GetFiles($d)){ $fn=[System.IO.Path]::GetFileName($fp); $fl=$fn.ToLowerInvariant(); if($fn.StartsWith('.tmp_idx_') -or ($skipFiles -contains $fl) -or $fl.StartsWith('ntuser.dat')){ continue }; $fi=[System.IO.FileInfo]::new($fp); $sz=[int64]$fi.Length; $tot+=$sz; $mt=[int64][math]::Floor(($fi.LastWriteTimeUtc - $ep).TotalSeconds); $ext=$fi.Extension.ToLowerInvariant(); $cat=if($ext -and $catMap.ContainsKey($ext)){ $catMap[$ext] }else{ 'other' }; $ec=if($ext){ $ext.TrimStart('.').ToUpperInvariant() }else{ '-' }; $p=$fp.Replace('\\','/'); $r=if($p.StartsWith($root)){ $p.Substring($root.Length) }else{ $fn }; $files.Add(@{ n=$fn; d=$mt; s=$sz; t=$cat; e=$ec; p=$p; r=$r }) } }catch{} }; " +
                "$cur=[System.IO.DriveInfo]::new($drv); $ct=[int64]$cur.TotalSize; $cf=[int64]$cur.AvailableFreeSpace; $cu=$ct-$cf; $cp=if($ct -gt 0){[math]::Round(($cu/$ct)*100,2)}else{0}; " +
                "$allDrives=@(); foreach($di in [System.IO.DriveInfo]::GetDrives()){ if($di.IsReady){ $dt=[int64]$di.TotalSize; $df=[int64]$di.AvailableFreeSpace; $du=$dt-$df; $dp=if($dt -gt 0){[math]::Round(($du/$dt)*100,2)}else{0}; $allDrives += @{ drive=$di.Name; root=$di.Name.Replace('\\','/'); total=$dt; used=$du; free=$df; percent_used=$dp; label=$di.VolumeLabel; kind=([string]$di.DriveType).ToLowerInvariant() } } }; " +
                "$pl=@{ generated_at=(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'); root=$root; drive=@{ drive=$rootWin; root=$root; total=$ct; used=$cu; free=$cf; percent_used=$cp; label=$cur.VolumeLabel; kind=([string]$cur.DriveType).ToLowerInvariant() }; drives=$allDrives; total_files=$files.Count; total_size=$tot; elapsed_sec=0.1; files=$files.ToArray() }; " +
                "$js=($pl | ConvertTo-Json -Depth 5 -Compress).Replace('</','<\\/'); $out=Join-Path $base 'files_index_data.js'; [System.IO.File]::WriteAllText($out, ('window.FILES_INDEX_DATA = ' + $js + ';' + [char]10), [System.Text.UTF8Encoding]::new($false))";

            ProcessStartInfo psi = new ProcessStartInfo(
                "powershell.exe",
                "-NoProfile -ExecutionPolicy Bypass -EncodedCommand " + EncodePsCommand(psScript));
            psi.EnvironmentVariables["FIS_DRV"] = driveRoot.TrimEnd('\\', '/');
            psi.EnvironmentVariables["FIS_BASE"] = baseDir;
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.WindowStyle = ProcessWindowStyle.Hidden;
            try
            {
                using (Process p = Process.Start(psi))
                {
                    if (p != null) p.WaitForExit(30000);
                }
            }
            catch { }
        }

        private static void OpenUrl(string url)
        {
            ProcessStartInfo psi = new ProcessStartInfo(url);
            psi.UseShellExecute = true;
            Process.Start(psi);
        }

        [STAThread]
        public static int Main(string[] args)
        {
            bool openDeleter = false;
            bool installMode = false;
            bool quietMode = false;
            int port = 8765;

            for (int i = 0; i < args.Length; i++)
            {
                string a = (args[i] ?? "").Trim().ToLowerInvariant();
                if (a == "--help" || a == "-h" || a == "/?")
                {
                    return 0;
                }
                if (a == "--deleter") openDeleter = true;
                else if (a == "--install") installMode = true;
                else if (a == "--quiet") quietMode = true;
                else if (a == "--port" && i + 1 < args.Length)
                {
                    int parsed;
                    if (int.TryParse(args[i + 1], out parsed) && parsed > 0 && parsed <= 65535)
                    {
                        port = parsed;
                    }
                    i++;
                }
            }

            string baseDir = AppDomain.CurrentDomain.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            string exePath = Process.GetCurrentProcess().MainModule.FileName;
            string driveRoot = Path.GetPathRoot(baseDir);
            if (string.IsNullOrEmpty(driveRoot)) driveRoot = baseDir;

            if (installMode)
            {
                string installErr;
                bool ok = InstallShortcuts(exePath, baseDir, out installErr);
                if (!quietMode)
                {
                    if (ok)
                    {
                        MessageBox.Show(
                            "Portable shortcuts created on Desktop and Start Menu pointing to:\n" + exePath,
                            "Osiris Suite Installer",
                            MessageBoxButtons.OK,
                            MessageBoxIcon.Information);
                    }
                    else
                    {
                        MessageBox.Show(
                            "Shortcut installation failed:\n" + installErr,
                            "Osiris Suite Installer",
                            MessageBoxButtons.OK,
                            MessageBoxIcon.Error);
                    }
                }
                return ok ? 0 : 1;
            }

            string targetUrl = "http://127.0.0.1:" + port + "/" + (openDeleter ? "deleter" : "");
            if (IsServerAlive(port))
            {
                OpenUrl(targetUrl);
                return 0;
            }

            string pyScript = Path.Combine(baseDir, "files_indexer.py");
            string pyExe = FindPythonExecutable(baseDir);

            if (!string.IsNullOrEmpty(pyExe) && File.Exists(pyScript))
            {
                string safeRootArg = driveRoot.TrimEnd('\\', '/') + "/";
                string pyArgs = string.Format(
                    "\"{0}\" --root \"{1}\" --port {2} --no-browser",
                    pyScript,
                    safeRootArg,
                    port);

                try
                {
                    ProcessStartInfo psi = new ProcessStartInfo(pyExe, pyArgs);
                    psi.WorkingDirectory = baseDir;
                    psi.UseShellExecute = false;
                    psi.CreateNoWindow = true;
                    psi.WindowStyle = ProcessWindowStyle.Hidden;
                    using (Process proc = Process.Start(psi)) { }

                    for (int w = 0; w < 45; w++)
                    {
                        Thread.Sleep(200);
                        if (IsServerAlive(port))
                        {
                            OpenUrl(targetUrl);
                            return 0;
                        }
                    }
                }
                catch { }
            }

            string offlineHtml = openDeleter
                ? Path.Combine(baseDir, "FILES INDEXATION_DELETER", "CHECKER_DELETER.html")
                : Path.Combine(baseDir, "FILES_INDEXATION_SYSTEM.html");

            if (!openDeleter)
            {
                RunPowerShellSnapshotFallback(driveRoot, baseDir);
            }

            if (File.Exists(offlineHtml))
            {
                OpenUrl(offlineHtml);
                return 0;
            }

            if (!quietMode)
            {
                MessageBox.Show(
                    "Could not start Osiris Indexer / Deleter server or find HTML UI in:\n" + baseDir,
                    "Osiris Suite",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            }
            return 1;
        }
    }
}
