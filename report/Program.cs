using System.Diagnostics;
using System.Net.Http;
using System.Runtime.CompilerServices;
using System.Timers;
using System.Management;
using System;
using System.Net.NetworkInformation;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using System.Net;
using YamlDotNet.Serialization.NamingConventions;
using YamlDotNet.Serialization;
using System.Security.Cryptography.X509Certificates;
using System.CodeDom.Compiler;
using Microsoft.Diagnostics.Tracing.StackSources;
using System.Net.Http.Headers;
using System.Text;

public class Suspect
{


    public List<TraceEvent> data = new List<TraceEvent>();
    int pid;

    public Suspect(int pid, TraceEvent data)
    {
        this.pid = pid;
        this.Add(data);
    }

    public void Add(TraceEvent ev)
    {
        data.Add(ev);
    }
}

public class DataBase
{
    public Dictionary<int, Suspect> suspects = new Dictionary<int, Suspect>();
    public Dictionary<string, int> events = new Dictionary<string, int>();
    public Dictionary<string, float> avgProcess = new Dictionary<string, float>();
    public Dictionary<string, float> avgCounters = new Dictionary<string, float>();
    public float avgCpu = 0;
    public float avgGpu = 0;

}

public class Global
{
    public List<int> childs = new List<int>();
}


static class Program
{
    
    static int waitTime = 10000;
    private static readonly HttpClient client = new HttpClient();
    private static System.Timers.Timer atimer;
    
    static string requestId = "";
    static string auth = "e63802c98228480e8d4447bb1ca3f3e1";
    static string name = "m1";
    static string nodeCode = "";
    static int timeSpan = 5;
    static bool verbose = false;


    static async Task Main()
    {
        client.DefaultRequestHeaders.Add("name", name);
        client.DefaultRequestHeaders.Add("auth", auth);
        atimer = new System.Timers.Timer(waitTime);
        atimer.Elapsed += new ElapsedEventHandler(GetNodeCode);
        Console.OutputEncoding = Encoding.UTF8;
        Console.WriteLine("Установка связи с сервером");

        //SendReport();
        atimer.Start();
        //Start();

        string input = "";
        try
        {
            while (input != "exit")
            {
                input = Console.ReadLine().ToString();
            }
            
        }
        catch (Exception)
        {

            throw;
        }
        

    }

    static async void GetNodeCode(Object? source, ElapsedEventArgs e)
    {
        string url = $"http://10.0.1.80:5000/nodes?id={name}";
        try
        {
            nodeCode = await client.GetStringAsync(url);
            switch (nodeCode)
            {
                case "0":
                    Console.WriteLine("Связь с сервером установлена"); break;

                case "1":
                    Console.WriteLine("Отправка статуса готовности"); Send_Ready(); break;

                case "2":
                    Console.WriteLine("Клиент готов к анализу файла"); break;

                case "3":
                    Console.WriteLine("Загрузка файла..."); GetFile(); break;

                case "4":
                    Console.WriteLine("Работа в процессе..."); break;

                

                case "6":
                    Console.WriteLine("Отчет отправлен. Ожидание вердикта."); CheckVerdict(); break;
                    

                default:
                    Console.WriteLine("Код не поддерживается"); break;
            }

        }
        catch (Exception er)
        {
            Console.WriteLine(er.Message);
        }
    }

    static async Task Send_Ready()
    {
        try
        {
            string url = "http://10.0.1.80:5000/ready";
            var response = await client.GetStringAsync(url);
            if (response == "ok")
            {
                Console.WriteLine("Клиен отмечен как 'ГОТОВ'");
            }
            else
            {
                Console.WriteLine("Сервер в очереди готовности");
            }
        }
        catch (Exception)
        {

            Console.WriteLine("[Error] Server is not available");
        }

    }

    static async Task GetFile()
    {
        try
        {
            string url1 = "http://10.0.1.80:5000/work?action=get_id";
            string url2 = "http://10.0.1.80:5000/work";
            requestId = await client.GetStringAsync(url1);

            var response = await client.GetStreamAsync(url2);

            using (var fs = new FileStream($".\\{requestId}", FileMode.CreateNew))
            {
                await response.CopyToAsync(fs);
            }
            Console.WriteLine("Файл загружен");

            
        }
        catch (Exception)
        {
            Console.WriteLine("[Error] Server is not available");
            //await Send_Ready();
        }
        int exitCode = Start();
    }

    static async Task SendReport()
    {
        client.DefaultRequestHeaders.Add("uuid", requestId);
        using (var formData = new MultipartFormDataContent())
        {
            var fileStreamContent = new StreamContent(File.OpenRead($"C:\\Test\\report.yml"));
            
            fileStreamContent.Headers.ContentType = new MediaTypeHeaderValue("text/yaml");
            formData.Add(fileStreamContent, "file", "file");
            
            
            var response = await client.PostAsync("http://10.0.1.80:5000/report", formData);
            string result = "";
            if (!response.IsSuccessStatusCode)
            {
                result = "fail";
            }
            else
            {
                result = await response.Content.ReadAsStringAsync();
                Console.WriteLine(result);
                if (result == "success") { nodeCode = "6"; }
            }
        }
    }

    static async Task CheckVerdict()
    {
        try
        {
            string url1 = $"http://10.0.1.80:5000/task?id={requestId}";
            string verdict = await client.GetStringAsync(url1);

            if (verdict == "malicious")
            {
                Console.WriteLine("Verdict was Malicious. Returning to Start State.");
                ProcessStartInfo proc = new ProcessStartInfo();
                proc.FileName = "cmd";
                proc.WindowStyle = ProcessWindowStyle.Hidden;
                proc.Arguments = "/C shutdown " + "-f -r -t 5";
                Process.Start(proc);
            }
            if (verdict == "clear")
            {
                Console.WriteLine("Чистый файл. Подготовка...");
                nodeCode = "1";
            }
            else
            {

                Console.WriteLine(verdict);
            }

            
        }
        catch (Exception)
        {
            Console.WriteLine("[Error] Server is not available");
        }
    }

    static IList<Process> GetChildProcesses(this Process process)
        => new ManagementObjectSearcher(
                $"Select * From Win32_Process Where ParentProcessID={process.Id}")
            .Get()
            .Cast<ManagementObject>()
            .Select(mo =>
                Process.GetProcessById(Convert.ToInt32(mo["ProcessID"])))
            .ToList();

    static IList<PerformanceCounter> RecheckGpuCounters()
    {
        string[] GpuInstancesNames = new PerformanceCounterCategory("GPU Engine").GetInstanceNames();
        IList<PerformanceCounter> GpuCounters = new List<PerformanceCounter>();

        foreach (var inst in GpuInstancesNames)
        {
            GpuCounters.Add(new PerformanceCounter(categoryName: "GPU Engine", counterName: "Utilization Percentage", instanceName: inst));
        }

        IList<PerformanceCounter> activeGpuCounters = new List<PerformanceCounter>();

        foreach (var counter in GpuCounters)
        {
            try
            {
                counter.NextValue();
                activeGpuCounters.Add(counter);
            }
            catch (Exception)
            {
                Debug.WriteLine("GPUCounterFailedAdd");
            }
        }

        return activeGpuCounters;
    }


    static IList<PerformanceCounter> Get_GPU_counters(Process p)
    {
        IList<PerformanceCounter> GpuCounters = new List<PerformanceCounter>();
        PerformanceCounterCategory GpuCategory = new PerformanceCounterCategory("GPU Engine");
        string[] GpuInstancesNames = GpuCategory.GetInstanceNames();

        IList<Process> childs = new List<Process>();

        childs = GetChildProcesses(p);

        childs.Add(p);

        foreach (var child in childs)
        {
            string instance = "";
            foreach (var inst in GpuInstancesNames)
            {
                if ((inst.Contains(child.Id.ToString())))
                {
                    instance = inst;
                    GpuCounters.Add(new PerformanceCounter(categoryName: "GPU Engine", counterName: "Utilization Percentage", instanceName: instance));
                }
            }
        }

        IList<PerformanceCounter> activeGpuCounters = new List<PerformanceCounter>();

        bool GpuFlag = false;

        foreach (var counter in GpuCounters)
        {
            try
            {
                counter.NextValue();
                activeGpuCounters.Add(counter);
                GpuFlag = true;
            }
            catch (Exception)
            {
                ;
            }
        }
        { if (verbose) { if (GpuFlag) { Console.WriteLine("GPU Counters found"); } else { Console.WriteLine("No GPU Checker"); } } }

        return activeGpuCounters;
    }

    static IList<PerformanceCounter> Get_Process_counters(Process p)
    {
        string[] counterNames = { "IO Data Bytes/sec", "IO Write Bytes/sec", "IO Read Bytes/sec",  };

        IList<PerformanceCounter> ProcessCounters = new List<PerformanceCounter>();
        IList<Process> childs = new List<Process>();
        childs = GetChildProcesses(p);
        childs.Add(p);

        foreach (var child in childs)
        {
            foreach (var counterName in counterNames)
            {
                try
                {
                    ProcessCounters.Add(new PerformanceCounter(categoryName: "Process", counterName: counterName, instanceName: child.ProcessName));
                }
                catch (Exception)
                {
                    Console.WriteLine($"Process {child.Id} exited");
                }
                
            }
        }

        IList<PerformanceCounter> activeProcessCounters = new List<PerformanceCounter>();

        bool Flag = false;

        foreach (var counter in ProcessCounters)
        {
            try
            {
                counter.NextValue();
                activeProcessCounters.Add(counter);
                Flag = true;
            }
            catch (Exception)
            {
                ;
            }
        }
        { if (verbose) { if (Flag) { Console.WriteLine("Process Counters found"); } else { Console.WriteLine("No Process Counters"); } } }

        return activeProcessCounters;
    }

    static IList<PerformanceCounter> Get_Other_counters(Process p)
    {
        
        string[] DiskcounterNames = { "% Disk Read Time", "% Idle Time"};
        string[] NetworkcounterNames = { "Bytes Received/sec", "Bytes Sent/sec" };
        string NetworkInterfaceName = "Realtek PCIe GbE Family Controller";


        IList<PerformanceCounter> Counters = new List<PerformanceCounter>();

        foreach (var counterName in DiskcounterNames)
        {
            Counters.Add(new PerformanceCounter(categoryName: "PhysicalDisk", counterName: counterName, instanceName: "_Total"));
        }
        foreach (var counterName in NetworkcounterNames)
        {
            Counters.Add(new PerformanceCounter(categoryName: "Network Interface", counterName: counterName, instanceName: NetworkInterfaceName));
        }

        IList<PerformanceCounter> activeCounters = new List<PerformanceCounter>();

        bool Flag = false;

        foreach (var counter in Counters)
        {
            try
            {
                counter.NextValue();
                activeCounters.Add(counter);
                Flag = true;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }
        { if (verbose) { if (Flag) { Console.WriteLine("Other Counters found"); } else { Console.WriteLine("No Other Counters"); } } }

        return activeCounters;
    }


    class SimpleOSEventMonitor
    {
        DataBase dataBase;
        Global settings;
        static string sessionName = "ETWProjectMEPHI";
        public TraceEventSession session = new TraceEventSession(sessionName);

        public SimpleOSEventMonitor(DataBase dataBase, Global settings)
        {
            this.dataBase = dataBase;
            this.settings = settings;
        }

        public void Run()
        {
            var monitoringTimeSec = 30;

            var firstEventTimeMSec = new Dictionary<int, double>();
            bool marker = false;
            bool end = false;


            string GetProcessOwner(int processId)
            {
                string query = "Select * From Win32_Process Where ProcessID = " + processId;
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);
                ManagementObjectCollection processList = searcher.Get();

                foreach (ManagementObject obj in processList)
                {
                    string[] argList = new string[] { string.Empty, string.Empty };
                    int returnVal = Convert.ToInt32(obj.InvokeMethod("GetOwner", argList));
                    if (returnVal == 0)
                    {
                        // return DOMAIN\user
                        return argList[1] + "\\" + argList[0];
                    }
                }

                return "NO OWNER";
            }

            static IPAddress UInt32ToIPAddress(Int32 ipAddress)
            {

                byte[] bytes = BitConverter.GetBytes(ipAddress);

                // flip little-endian to big-endian(network order)
                if (BitConverter.IsLittleEndian)
                {
                    Array.Reverse(bytes);
                }

                return new IPAddress(bytes);
            }

            session.Source.Dynamic.All += delegate (TraceEvent data)
            {
                if (settings.childs.Contains(data.ProcessID))
                {

                    //string eventString = data.ToString();
                    //Debug.WriteLine(eventString);

                    string[] filter = { "DeletePath" };

                    if (dataBase.events.ContainsKey(data.EventName))
                    {
                        dataBase.events[data.EventName] += 1;
                    }
                    else
                    {
                        dataBase.events[data.EventName] = 1;
                    }

                    if (dataBase.suspects.ContainsKey(data.ProcessID))
                    {
                        dataBase.suspects[data.ProcessID].Add(data);
                    }
                    else
                    {
                        dataBase.suspects.Add(data.ProcessID, new Suspect(data.ProcessID, data));
                    }

                    //Console.WriteLine(GetProcessOwner(data.ProcessID));


                    //using (var p = Process.GetProcessById(data.ProcessID)) { Console.WriteLine(p.ProcessName); }

                    //Console.WriteLine(data.PayloadIndex("FilePath"));

                    //Out.WriteLine(data.PayloadString(6));

                    //Out.WriteLine("GOT Event Delay={0:f1}sec: {1} ", delay, data.ToString());


                    //Out.WriteLine(GetProcessOwner(8444));

                }
            };

            var restarted = session.EnableProvider("Microsoft-Windows-Kernel-Network");
            session.EnableProvider("Microsoft-Windows-Kernel-File");
            session.EnableProvider("Circular Kernel Session Provider");
            session.EnableProvider("Windows Kernel Trace");
            session.EnableProvider("Microsoft-Windows-Audio");

            session.Source.Process();


        }
    }

    static int Start()
    {
        Global settings = new Global();
        ProcessStartInfo startInfo = new ProcessStartInfo();
        startInfo.FileName = $".\\{requestId}";
        //startInfo.FileName = $"C:\\Program Files (x86)\\Geeks3D\\Benchmarks\\FurMark\\FurMark.exe";
        //startInfo.FileName = $"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
        //startInfo.FileName = $"notepad.exe";
        //startInfo.Arguments = "& '/nogui /width=1024 /height=728 /noscore /log_gpu_data_polling_factor=10 /max_time=10000'";
        //startInfo.RedirectStandardOutput = true;
        //startInfo.RedirectStandardError = true;
        //startInfo.UseShellExecute = false;
        //startInfo.CreateNoWindow = true;

        int[] childIds = { };

        bool started = false;
        var p = new Process();

        p.StartInfo = startInfo;

        try //start process
        {
            started = p.Start();
        }
        catch (InvalidOperationException)
        {
            started = false;
            
        }
        catch (Exception ex)
        {
            started = false;
            
        }

        //Thread.Sleep(5000); //Ждем запуска процесса

        Console.WriteLine($"{p.Id}:{p.ProcessName}:");
        IList<Process> childs = new List<Process>();

        childs = GetChildProcesses(p);

        string childsID = "";
        settings.childs.Clear();
        foreach (var child in childs)
        {
            settings.childs.Add(child.Id);
            childsID += child.Id.ToString() + ",";
        }

        Console.WriteLine($"{p.Id}_Childs:[{childsID}]");

        childs.Add(p);

        float tmp;
        float avgCpu = 0;
        float avgGpu = 0;

        // Start Etw Session Block

        DataBase ResultData = new DataBase();


        SimpleOSEventMonitor monitor = new SimpleOSEventMonitor(ResultData, settings);

        Thread thread1 = new Thread(monitor.Run);

        thread1.Start();

        //End Etw Session Block


        Dictionary<string, float> avgProcess = new Dictionary<string, float>();
        Dictionary<string, float> avgCounters = new Dictionary<string, float>();

        PerformanceCounter CpuCounter =
                      new PerformanceCounter(categoryName: "Processor", counterName: "% Processor Time", instanceName: "_Total");
        CpuCounter.NextValue();
        IList<PerformanceCounter> activeOtherCounters = Get_Other_counters(p);

        

        for (int i = 0; i < timeSpan; i++)
        {
            IList<PerformanceCounter> activeProcessCounters = Get_Process_counters(p);
            IList<PerformanceCounter> activeGpuCounters = Get_GPU_counters(p);
            
            Dictionary<string, int> avgProcessCnt = new Dictionary<string, int>();
            Thread.Sleep(1000);

            settings.childs.Clear();
            foreach (var child in childs)
            {
                settings.childs.Add(child.Id);
                childsID += child.Id.ToString() + ",";
            }

            if (activeGpuCounters.Count() >= 1)
            {
                foreach (var counter in activeGpuCounters)
                {
                    tmp = counter.NextValue();
                    //Console.WriteLine(tmp);
                    avgGpu += tmp;

                }

            }
            if (activeProcessCounters.Count() >= 1)
            {
                avgProcessCnt.Clear();
                foreach (var counter in activeProcessCounters)
                {
                    tmp = counter.NextValue();
                    //Console.WriteLine(tmp);
                    if (avgProcess.ContainsKey($"{counter.CounterName}")) { avgProcess[$"{counter.CounterName}"] += tmp;  }
                    else { avgProcess[$"{counter.CounterName}"] = tmp;  }
                    if (avgProcessCnt.ContainsKey($"{counter.CounterName}")) { avgProcessCnt[$"{counter.CounterName}"] += 1; }
                    else { avgProcessCnt[$"{counter.CounterName}"] = 1; }
                }

            }
            foreach (var counter in activeProcessCounters)
            {
                avgProcess[$"{counter.CounterName}"] /= avgProcessCnt[$"{counter.CounterName}"];
            }
            tmp = CpuCounter.NextValue();
            avgCpu += tmp;

            if (activeOtherCounters.Count() >= 1)
            {
                foreach (var counter in activeOtherCounters)
                {
                    tmp = counter.NextValue();
                    //Console.WriteLine(tmp);
                    if (avgCounters.ContainsKey($"{counter.CounterName}")) { avgCounters[$"{counter.CounterName}"] += tmp; }
                    else { avgCounters[$"{counter.CounterName}"] = tmp; }
                    
                }

            }

        }

        monitor.session.Source.StopProcessing();
        monitor.session.Dispose();

        avgCpu /= timeSpan;
        avgGpu /= timeSpan;

        foreach (var item in avgProcess)
        {
            Console.WriteLine($"{item.Key}: {item.Value / timeSpan}");
        }
        foreach (var item in avgCounters)
        {
            Console.WriteLine($"{item.Key}: {item.Value / timeSpan}");
        }

        Console.WriteLine($"AverageCPU:{avgCpu}");
        Console.WriteLine($"AverageGPU:{avgGpu}");

        ResultData.avgCpu = avgCpu;
        ResultData.avgGpu = avgGpu;
        ResultData.avgCounters = avgCounters;
        ResultData.avgProcess = avgProcess;

        Console.WriteLine("ETW Results:");
        foreach (var item in ResultData.events)
        {
            Console.WriteLine($"{item.Key}:{item.Value}");
        }

        p.Kill();
        SaveReport(ResultData);

        return 1;





    }

    class SerYaml
    {
        public float AvgCpu { get; set; }
        public float AvgGpu { get; set; }
        public Dictionary<string, float> avgCounters { get; set; }
        public Dictionary<string, float> avgProcess { get; set; }
        public Dictionary<string, int> events { get; set; }
    }

    public static void SaveReport(DataBase data)
    {
        var report = new SerYaml();
        report.AvgCpu = data.avgCpu;
        report.AvgGpu = data.avgGpu;
        report.avgProcess = data.avgProcess;
        report.avgCounters = data.avgCounters;
        report.events = data.events;
        //config.GpuMarker = Marker.GpuMarker.ToString();
        //config.GpuTable = new List<string>();
        //config.CpuTable = new List<string>();
        //foreach (var item in Marker.GpuTable)
        //{
        //    config.GpuTable.Add(item.ToString());
        //}
        //foreach (var item in Marker.CpuTable)
        //{
        //    config.CpuTable.Add(item.ToString());
        //}

        var serializer = new SerializerBuilder()
            .WithNamingConvention(CamelCaseNamingConvention.Instance)
            .Build();

        var stringResult = serializer.Serialize(report);

        File.WriteAllText("C:\\Test\\report.yml", stringResult);


        Console.WriteLine("Work done. Sending report."); 
        SendReport();
    }





}

