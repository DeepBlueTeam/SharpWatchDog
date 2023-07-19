using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using System.Security.Principal;
using Microsoft.O365.Security.ETW;
using System;
using System.Diagnostics;
using System.Text;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Threading;

namespace SharpWatchDog
{
    internal class Program
    {
        static List<Rule> Rules = new List<Rule>();
        static bool work1 = false;
        static bool work2 = false;
        static string hostname;
        static string ip;
        static ConcurrentQueue<string> Messages = new ConcurrentQueue<string>();


        //todo 当前主机名及ip获取，放入到消息中
        //todo 主机太多的时候，同一个token会导致发送消息频率不可控制，需要先发到一个统一的消息处理网关去转发
        static void MessageSendThread()
        {
            List<string> messageCache = new List<string>();
            DateTime lastSend = DateTime.Now;
            while (true)
            {
                Thread.Sleep(1000);
                //dingding接口限制每分钟只能发20条
                if ((DateTime.Now - lastSend).TotalSeconds > 3 && messageCache.Count > 0)
                {
                    if (dingding.push(string.Join("\n\n", messageCache) + "\n---"))
                    {
                        messageCache.Clear();
                        lastSend = DateTime.Now;
                    }
                }
                string temp;
                if (Messages.TryDequeue(out temp))
                {
                    messageCache.Add(temp);
                }
                else
                {
                    continue;
                }
            }
        }
      
        static void SecurityThread()
        {
            //https://learn.microsoft.com/zh-cn/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor
            Dictionary<int, String> EventIdMap = new Dictionary<int, String>();
            EventIdMap.Add(4724, "尝试重置帐户的密码");
            EventIdMap.Add(4648, "尝试使用显式凭据登录");
            EventIdMap.Add(4624, "帐户登录成功");
            EventIdMap.Add(4625, "无法登录帐户");

            var trace = new UserTrace("EventLog-Security");
            var provider = new Provider("Microsoft-Windows-Security-Auditing");
            provider.Any = Provider.AllBitsSet;
            provider.OnEvent += (record) =>
            {
                //可以根据自己的需求增加需要处理的事件ID，事件有哪些参数参考项目 https://github.com/zodiacon/EtwExplorer
                if (record.Id == 4648 || record.Id == 4624 || record.Id == 4625 || record.Id == 4724)
                {
                    foreach (Rule rule in Rules)
                    {
                        if (rule.ruleType == "logon")
                        {
                            string v = record.GetUnicodeString(rule.ruleField, "");
                            if (!Compare.Test(rule.ruleOpr, v, rule.ArgString, rule.ArgStringList))
                            {
                                continue;
                            }
                            string eventName;
                            EventIdMap.TryGetValue(record.Id, out eventName);
                            List<string> listinfo = new List<string>();
                            listinfo.Add($"规则: {rule.ruleName}");
                            listinfo.Add($"事件: {eventName}");
                            listinfo.Add($"时间: {record.Timestamp.ToLocalTime().ToString()}");
                            listinfo.Add($"进程ID: {record.GetInt64("ProcessId", 0)}");
                            listinfo.Add($"进程名: {record.GetUnicodeString("ProcessName", "")}");
                            listinfo.Add($"TargetDomainName: {record.GetUnicodeString("TargetDomainName", "")}");
                            listinfo.Add($"TargetUserName  : {record.GetUnicodeString("TargetUserName", "")}");
                            listinfo.Add($"IpAddress       : {record.GetUnicodeString("IpAddress", "")}");
                            listinfo.Add($"IpPort          : {record.GetUnicodeString("IpPort", "")}");
                            listinfo.Add($"WorkstationName : {record.GetUnicodeString("WorkstationName", "")}");
                            Messages.Enqueue(string.Join("\n", listinfo));
                        }
                    }
                }
            };
            trace.Enable(provider);
            work1 = true;
            trace.Start();            
        }

        static void KernelThread()
        {
            using (TraceEventSession session = new TraceEventSession("KernelWatchDog"))
            {
                int[] need_event_type =
                {
                    (int)KernelTraceEventParser.Keywords.Process,
                    (int)KernelTraceEventParser.Keywords.FileIO,
                    (int)KernelTraceEventParser.Keywords.FileIOInit,
                    (int)KernelTraceEventParser.Keywords.NetworkTCPIP,
                };
                int mask = 0;
                foreach (int i in need_event_type)
                {
                    mask = mask | i;
                }
                //有时可能会失败，再执行一次就好了
                //session.EnableKernelProvider((KernelTraceEventParser.Keywords)mask);
                bool testOk = false;
                for (int i = 0; i < 3; i++)
                {
                    try
                    {
                        session.EnableKernelProvider((KernelTraceEventParser.Keywords)mask);
                        testOk = true;
                        break;
                    }
                    catch
                    {
                        Thread.Sleep(2000);
                    }
                }
                if (!testOk)
                {
                    Console.WriteLine("工作线程不正常，需要重新启动");
                    Process.GetCurrentProcess().Kill();
                }
                Console.WriteLine("StartUp ok!");
                session.Source.Kernel.ProcessStart += delegate (ProcessTraceData data)
                {
                    foreach (Rule rule in Rules)
                    {
                        bool isNeed = false;
                        if (rule.ruleType == "process" && rule.ruleField == "ProcessName" && Compare.Test(rule.ruleOpr, data.ProcessName, rule.ArgString, rule.ArgStringList))
                        {
                            isNeed = true;
                        }
                        if (rule.ruleType == "process" && rule.ruleField == "CommandLine" && Compare.Test(rule.ruleOpr, data.CommandLine, rule.ArgString, rule.ArgStringList))
                        {
                            isNeed = true;
                        }
                        if (isNeed)
                        {
                            List<string> listinfo = new List<string>();
                            listinfo.Add($"规则: {rule.ruleName}");
                            listinfo.Add($"时间: {data.TimeStamp.ToLocalTime().ToString()}");
                            listinfo.Add($"进程ID: {data.ProcessID}");
                            listinfo.Add($"进程名: {data.ProcessName}");
                            listinfo.Add($"父进程ID: {data.ParentID}");
                            listinfo.Add($"CommandLine: {data.CommandLine}");
                            Messages.Enqueue(string.Join("\n", listinfo));
                            //防止多次通知，不要的话单个事件可能命中多个规则，会通知多次
                            //break;
                        }
                    }

                };

                session.Source.Kernel.FileIOWrite += delegate (FileIOReadWriteTraceData data)
                {
                    if (data.EventName == "FileIO/Write" && data.ProcessName != "")
                    {
                        foreach (Rule rule in Rules)
                        {
                            bool isNeed = false;
                            if (rule.ruleType == "file" && rule.ruleField == "FileName" && Compare.Test(rule.ruleOpr, data.FileName, rule.ArgString, rule.ArgStringList))
                            {
                                isNeed = true;
                            }
                            if (isNeed)
                            {
                                List<string> listinfo = new List<string>();
                                listinfo.Add($"规则: {rule.ruleName}");
                                listinfo.Add($"时间: {data.TimeStamp.ToLocalTime().ToString()}");
                                listinfo.Add($"进程ID: {data.ProcessID}");
                                listinfo.Add($"进程名: {data.ProcessName}");
                                listinfo.Add($"FileName: {data.FileName}");
                                listinfo.Add($"IoSize  : {data.IoSize}");
                                Messages.Enqueue(string.Join("\n", listinfo));
                                //防止多次通知，不要的话单个事件可能命中多个规则，会通知多次
                                //break;
                            }
                        }
                    }
                };
              
                
                Action<TcpIpConnectTraceData> networkAction = delegate (TcpIpConnectTraceData data)
                {
                    foreach (Rule rule in Rules)
                    {
                        bool isNeed = false;
                        if (rule.ruleType == "network" && rule.ruleField == "dport" && Compare.Test(rule.ruleOpr, data.dport.ToString(), rule.ArgString, rule.ArgStringList))
                        {
                            isNeed = true;
                        }
                        if (isNeed)
                        {
                            List<string> listinfo = new List<string>();
                            listinfo.Add($"规则: {rule.ruleName}");
                            listinfo.Add($"时间: {data.TimeStamp.ToLocalTime().ToString()}");
                            listinfo.Add($"进程ID: {data.ProcessID}");
                            listinfo.Add($"进程名: {data.ProcessName}");
                            listinfo.Add($"源地址  : {data.saddr}:{data.sport}");
                            listinfo.Add($"目的地址: {data.daddr}:{data.dport}");
                            Messages.Enqueue(string.Join("\n", listinfo));
                            //防止多次通知，不要的话单个事件可能命中多个规则，会通知多次
                            //break;
                        }
                    }
                };

                session.Source.Kernel.TcpIpAccept += networkAction;
                session.Source.Kernel.TcpIpConnect += networkAction;

                //session.Source.UnhandledEvents += delegate (TraceEvent data)
                //{
                //    StringBuilder sb = new StringBuilder();
                //    data.ToXml(sb);
                //    Console.WriteLine(sb.ToString());
                //};

                work2 = true;
                session.Source.Process();                
            }
        }


        static void Main(string[] args)
        {
            Rules = YmlParser.parse("config.yml");
            if (TraceEventSession.IsElevated() != true)
            {
                Console.WriteLine("Must be elevated (Admin) to run this program.");
                return;
            }

            new Thread(delegate ()
            {
                SecurityThread();
            }).Start();

            new Thread(delegate ()
            {
                KernelThread();
            }).Start();

            new Thread(delegate ()
            {
                MessageSendThread();
            }).Start();

            while (true)
            {
                Thread.Sleep(10000);
                if (!work1 || !work2)
                {
                    Console.WriteLine("工作线程不正常，需要重新启动");
                    Process.GetCurrentProcess().Kill();
                }
            }




        }
    }
}
