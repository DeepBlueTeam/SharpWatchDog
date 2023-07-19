using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpWatchDog
{
    public class Compare
    {
        public static bool Test(string opr, string v, string arg, List<string> arglist)
        {
            bool bok = false;
            switch (opr)
            {
                case "eq":
                    if (v.ToLower() == arg.ToLower())
                    {
                        bok = true;
                    }
                    break;
                case "ne":
                    if (v.ToLower() != arg.ToLower())
                    {
                        bok = true;
                    }
                    break;
                case "gt":
                    if (v.CompareTo(arg) > 0)
                    {
                        bok = true;
                    }
                    break;
                case "lt":
                    if (v.CompareTo(arg) < 0)
                    {
                        bok = true;
                    }
                    break;
                case "like":
                    foreach(string need in arglist)
                    {
                        if (need.EndsWith("*")){
                            if (v.ToLower().StartsWith(need.ToLower().TrimEnd('*')))
                            {
                                bok = true;
                                break;
                            }
                        }else if (need.StartsWith("*")){
                            if (v.ToLower().EndsWith(need.ToLower().TrimStart('*')))
                            {
                                bok = true;
                                break;
                            }
                        } else {
                            if (v.ToLower().Contains(need.ToLower()))
                            {
                                bok = true;
                                break;
                            }                           
                        }
                    }
                    break;
                case "in":
                    foreach (string need in arglist)
                    {
                        if (v.ToLower() == need.ToLower())
                        {
                            bok = true;
                            break;
                        }
                    }
                    break;
                default:
                    break;
            }
            return bok;
        }
    }
}
