using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using YamlDotNet.Serialization.NamingConventions;
using YamlDotNet.Serialization;
using static Microsoft.Diagnostics.Tracing.Analysis.GC.TraceGC;

namespace SharpWatchDog
{
    public class Rule
    {
        public string ruleType;
        public string ruleName;
        public string ruleField;
        public string ruleOpr;
        public string ArgString;
        public List<string> ArgStringList;
    }

    public class YmlParser
    {
        public static string dingdingtoken = "";
        public static List<Rule> parse(string ymlpath)
        {
            List<Rule> rules = new List<Rule>();
            var deserializer = new DeserializerBuilder().WithNamingConvention(CamelCaseNamingConvention.Instance).Build();
            System.Collections.Generic.Dictionary<object, object> result = (System.Collections.Generic.Dictionary<object, object>)deserializer.Deserialize(File.OpenText("config.yml"));

            object o_dingding;
            if (result.TryGetValue("dingdingtoken", out o_dingding))
            {
                dingdingtoken = o_dingding.ToString();
            }
                

            foreach (string tempType in new string[]{"logon", "process", "network", "file"}){
                object o_top;
                if (!result.TryGetValue(tempType, out o_top))
                {
                    continue;
                }
                List<object> o_top_list = (List<object>)o_top;
                foreach(object o_rule in o_top_list)
                {
                    System.Collections.Generic.Dictionary<object, object> o_rule_map = (System.Collections.Generic.Dictionary<object, object>)o_rule;
                    Rule tempRule = new Rule();
                    tempRule.ruleType = tempType;
                    tempRule.ArgStringList = new List<string>();
                    foreach (var item in o_rule_map)
                    {
                        string k = item.Key.ToString();
                        if (k == "rulename")
                        {
                            tempRule.ruleName = item.Value.ToString();
                        }
                        string[] field_opr = k.Split('_');
                        if (field_opr.Length == 2)
                        {
                            tempRule.ruleField = field_opr[0];
                            tempRule.ruleOpr = field_opr[1];
                            if (tempRule.ruleOpr == "eq" || tempRule.ruleOpr == "ne" || tempRule.ruleOpr == "gt" || tempRule.ruleOpr == "lt")
                            {
                                tempRule.ArgString = item.Value.ToString();
                            }
                            else
                            {
                                foreach(string vv in (List<object>)item.Value)
                                {
                                    tempRule.ArgStringList.Add(vv);
                                }
                            }
                        }
                    }
                    rules.Add(tempRule);
                }
                
            }

            return rules;
        }
    }
  

}
