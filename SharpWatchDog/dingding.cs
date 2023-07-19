using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Security;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace SharpWatchDog
{
    internal class dingding
    {
        public static bool push(string info)
        {
            if (YmlParser.dingdingtoken == "")
            {
                return true;
            }
            try
            {
                string temp = "{\"msgtype\": \"text\",\"text\": {\"content\":\""+info+"---\"}}";
                byte[] data = Encoding.UTF8.GetBytes(temp);

                long ts = new DateTimeOffset(DateTime.UtcNow).Ticks;
                string tempurl = string.Format("https://oapi.dingtalk.com/robot/send?access_token={0}", YmlParser.dingdingtoken);
                HttpWebRequest request;
                request = WebRequest.Create(tempurl) as HttpWebRequest;
                request.Timeout = 20 * 1000;
                //request.KeepAlive = true;
                request.Method = "POST";
                request.ContentType = "application/json";
                request.ContentLength = data.Length;
                request.AllowAutoRedirect = false;
                Stream requestStream = request.GetRequestStream();
                requestStream.Write(data, 0, data.Length);
                requestStream.Close();
                HttpWebResponse response = request.GetResponse() as HttpWebResponse;
                Stream responseStream = response.GetResponseStream();
                StreamReader sr = new StreamReader(responseStream);
                string responseText = sr.ReadToEnd();
                return true;
            }
            catch (Exception ex)
            {
                return false;
            }
        }
    }
}
