/*
	Copyright (c) 2011, pGina Team
	All rights reserved.

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are met:
		* Redistributions of source code must retain the above copyright
		  notice, this list of conditions and the following disclaimer.
		* Redistributions in binary form must reproduce the above copyright
		  notice, this list of conditions and the following disclaimer in the
		  documentation and/or other materials provided with the distribution.
		* Neither the name of the pGina Team nor the names of its contributors 
		  may be used to endorse or promote products derived from this software without 
		  specific prior written permission.

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
	ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
	WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
	DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY
	DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
	(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
	LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
	ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
	(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
	SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Net.NetworkInformation;

using log4net;

using OpenCredential.Shared.Interfaces;
using OpenCredential.Shared.Types;
using OpenCredential.Shared.Settings;


namespace OpenCredential.Plugin.RADIUS
{
    public class RADIUSPlugin : IPluginConfiguration, IPluginAuthentication, IPluginAuthorization, IPluginAuthenticationGateway, IPluginEventNotifications
    {
        private ILog m_logger = LogManager.GetLogger("RADIUSPlugin");
        public static Guid SimpleUuid = new Guid("{350047A0-2D0B-4E24-9F99-16CD18D6B142}");
        private string m_defaultDescription = "A RADIUS Authentication, Authorization and Accounting Plugin";
        private dynamic m_settings = null;
        private Dictionary<Guid, Session> m_sessionManager;

        public RADIUSPlugin()
        {
            using(Process me = Process.GetCurrentProcess())
            {
                m_settings = new OpenCredentialDynamicSettings(SimpleUuid);
                m_settings.SetDefault("ShowDescription", true);
                m_settings.SetDefault("Description", m_defaultDescription);

                m_sessionManager = new Dictionary<Guid, Session>();
                
                m_logger.DebugFormat("Plugin initialized on {0} in PID: {1} Session: {2}", Environment.MachineName, me.Id, me.SessionId);
            }            
        }        

        public string Name
        {
            get { return "RADIUS Plugin"; }
        }

        public string Description
        {
            get { return m_settings.Description; }
        }

        public string Version
        {
            get
            {
                return System.Reflection.Assembly.GetExecutingAssembly().GetName().Version.ToString();
            }
        }

        public Guid Uuid
        {
            get { return SimpleUuid; }
        }

        // Authenticates user
        public BooleanResult AuthenticateUser(SessionProperties properties)
        {
            m_logger.DebugFormat("AuthenticateUser({0})", properties.Id.ToString());

            if (!(bool)Settings.Store.GetSetting("EnableAuth", true))
            {
                m_logger.Debug("Authentication stage set on RADIUS plugin but authentication is not enabled in plugin settings.");
                return new BooleanResult() { Success = false };
            }

            // Get user info
            UserInformation userInfo = properties.GetTrackedSingle<UserInformation>();

            if(String.IsNullOrEmpty(userInfo.Username) || String.IsNullOrEmpty(userInfo.Password))
                return new BooleanResult() { Success = false, Message = "Username and password must be provided." };

            try
            {
                RADIUSClient client = GetClient(); 
                bool result = client.Authenticate(userInfo.Username, userInfo.Password);
                if (result)
                {
                    Session session = new Session(properties.Id, userInfo.Username, client);
                    Packet p = client.lastReceievedPacket;

                    // Check for session timeout
                    if ((bool)Settings.Store.GetSetting("AllowSessionTimeout", false) && p.containsAttribute(Packet.AttributeType.Session_Timeout))
                    {   
                        int seconds = client.lastReceievedPacket.getFirstIntAttribute(Packet.AttributeType.Session_Timeout);
                        session.SetSessionTimeout(seconds, SessionTimeoutCallback);
                    }

                    if (p.containsAttribute(Packet.AttributeType.Idle_Timeout))
                    {
                        int seconds = client.lastReceievedPacket.getFirstIntAttribute(Packet.AttributeType.Idle_Timeout);
                    }

                    if(p.containsAttribute(Packet.AttributeType.Vendor_Specific)){
                        foreach(byte[] val in p.getByteArrayAttributes(Packet.AttributeType.Vendor_Specific)){
                            if ((bool)Settings.Store.GetSetting("WisprSessionTerminate", false) && Packet.VSA_vendorID(val) == (int)Packet.VSA_WISPr.Vendor_ID 
                                && Packet.VSA_VendorType(val) == (int)Packet.VSA_WISPr.WISPr_Session_Terminate_Time)
                            {
                                try
                                {
                                    string sdt = Packet.VSA_valueAsString(val);
                                    DateTime dt = DateTime.ParseExact(sdt, "yyyy-MM-dd'T'HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture);

                                    if (dt > DateTime.Now)
                                    {
                                        session.Set_Session_Terminate(dt, SessionTerminateCallback);
                                    }
                                    else
                                        m_logger.DebugFormat("The timestamp provided for WisperSessionTerminate time value has passed.");
                                }
                                catch (FormatException)
                                {
                                    m_logger.DebugFormat("Unable to parse timestamp: {0}", Packet.VSA_valueAsString(val));
                                }
                            }
                        }
                    }

                    // Check for interim-update
                    if ((bool)Settings.Store.GetSetting("SendInterimUpdates", false))
                    {
                        int seconds = 0;

                        if (p.containsAttribute(Packet.AttributeType.Acct_Interim_Interval))
                        {
                            seconds = client.lastReceievedPacket.getFirstIntAttribute(Packet.AttributeType.Acct_Interim_Interval);
                        }

                        if ((bool)Settings.Store.GetSetting("ForceInterimUpdates", false))
                        {
                            int forceTime = (int)Settings.Store.GetSetting("InterimUpdateTime", 900);
                            if (forceTime > 0)
                                seconds = forceTime;
                        }

                        if (seconds > 0)
                        {
                            session.SetInterimUpdate(seconds, InterimUpdatesCallback);
                            m_logger.DebugFormat("Setting interim update interval for {0} to {1} seconds.", userInfo.Username, seconds);
                        }
                        else
                        {
                            m_logger.DebugFormat("Interim Updates are enabled, but no update interval was provided by the server or user.");
                        }
                    }

                    lock (m_sessionManager)
                    {
                        m_sessionManager.Add(session.id, session);
                    }

                    string message = null;
                    if (p.containsAttribute(Packet.AttributeType.Reply_Message))
                        message = p.getFirstStringAttribute(Packet.AttributeType.Reply_Message);

                    return new BooleanResult() { Success = result, Message = message };
                }

                string msg = "Unable to validate username or password.";

                if (client.lastReceievedPacket == null)
                {
                    msg = msg + " No response from server.";
                }
                else if (client.lastReceievedPacket.containsAttribute(Packet.AttributeType.Reply_Message))
                {
                    msg = client.lastReceievedPacket.getFirstStringAttribute(Packet.AttributeType.Reply_Message);
                }
                else if (client.lastReceievedPacket.code == Packet.Code.Access_Reject)
                {
                    msg = msg + " Access Rejected.";
                }

                return new BooleanResult() { Success = result, Message = msg };
            }
            catch (RADIUSException re)
            {
                m_logger.Error("An error occurred during while authenticating.", re);
                return new BooleanResult() { Success = false, Message = re.Message };
            }
            catch (Exception e)
            {
                m_logger.Error("An unexpected error occurred while authenticating.", e);
                throw;
            }
        }

        // Authorize user
        public BooleanResult AuthorizeUser(SessionProperties properties)
        {
            m_logger.Debug("RADIUS Plugin Authorization");

            if (!(bool)Settings.Store.GetSetting("EnableAuthz", true))
            {
                m_logger.Debug("RADIUS Authorization is not enabled.");
                return new BooleanResult() { Success = true };
            }

            bool requireSuccess = (bool)Settings.Store.GetSetting("AuthzRequireSuccess", true);
            if (requireSuccess && !WeAuthedThisUser(properties))
            {
                m_logger.InfoFormat("Deny because RADIUS auth failed or did not run, and configured to require RADIUS auth success.");
                return new BooleanResult()
                {
                    Success = false,
                    Message = "RADIUS authentication did not succeed."
                };
            }

            return new BooleanResult() { Success = true };
        }

        private bool WeAuthedThisUser(SessionProperties properties)
        {
            PluginActivityInformation actInfo = properties.GetTrackedSingle<PluginActivityInformation>();
            try
            {
                BooleanResult result = actInfo.GetAuthenticationResult(this.Uuid);
                return result.Success;
            }
            catch (KeyNotFoundException)
            {
                return false;
            }
        }

        // Gateway logic (assign configured local group)
        public BooleanResult AuthenticatedUserGateway(SessionProperties properties)
        {
            m_logger.Debug("RADIUS Plugin Gateway");

            if (!(bool)Settings.Store.GetSetting("EnableGateway", true))
            {
                m_logger.Debug("RADIUS Gateway is not enabled.");
                return new BooleanResult() { Success = true };
            }

            try
            {
                UserInformation userInfo = properties.GetTrackedSingle<UserInformation>();
                string localGroup = (string)Settings.Store.GetSetting("GatewayLocalGroup", "Users");
                if (!string.IsNullOrEmpty(localGroup))
                {
                    m_logger.InfoFormat("Adding user {0} to local group {1} (RADIUS gateway)", userInfo.Username, localGroup);
                    userInfo.AddGroup(new GroupInformation() { Name = localGroup });
                    return new BooleanResult() { Success = true, Message = string.Format("Added to group: {0}", localGroup) };
                }
            }
            catch (Exception e)
            {
                m_logger.ErrorFormat("Error during gateway: {0}", e);
                return new BooleanResult() { Success = true, Message = e.Message };
            }

            return new BooleanResult() { Success = true, Message = "No groups added." };
        }

        // Processes accounting on logon/logoff
        public void SessionChange(System.ServiceProcess.SessionChangeDescription changeDescription, OpenCredential.Shared.Types.SessionProperties properties)
        {
            if (changeDescription.Reason != System.ServiceProcess.SessionChangeReason.SessionLogon
                && changeDescription.Reason != System.ServiceProcess.SessionChangeReason.SessionLogoff)
            {
                return;
            }

            if (properties == null)
            {
                return;
            }

            if (!(bool)Settings.Store.GetSetting("EnableAcct", false))
            {
                m_logger.Debug("Session Change stage set on RADIUS plugin but accounting is not enabled in plugin settings.");
                return;
            }

            string username;
            UserInformation ui = properties.GetTrackedSingle<UserInformation>();

            if (ui == null)
            {
                return;
            }

            if ((bool)Settings.Store.GetSetting("UseModifiedName", false))
                username = ui.Username;
            else
                username = ui.OriginalUsername;

            Session session = null;

            if (changeDescription.Reason == System.ServiceProcess.SessionChangeReason.SessionLogon)
            {
                lock (m_sessionManager)
                {
                    if (!m_sessionManager.Keys.Contains(properties.Id))
                    {
                        if(!(bool)Settings.Store.GetSetting("AcctingForAllUsers", false)){
                            return;
                        }

                        RADIUSClient client = GetClient();
                        session = new Session(properties.Id, username, client);
                        m_sessionManager.Add(properties.Id, session);
                            
                        if ((bool)Settings.Store.GetSetting("SendInterimUpdates", false) && (bool)Settings.Store.GetSetting("ForceInterimUpdates", false))
                        {
                            int interval = (int)Settings.Store.GetSetting("InterimUpdateTime", 900);
                            session.SetInterimUpdate(interval, InterimUpdatesCallback);
                        }
                    }
                    else
                        session = m_sessionManager[properties.Id];
                }

                PluginActivityInformation pai = properties.GetTrackedSingle<PluginActivityInformation>();
                Packet.Acct_Authentic authSource = Packet.Acct_Authentic.Not_Specified;
                IEnumerable<Guid> authPlugins = pai.GetAuthenticationPlugins();
                Guid LocalMachinePluginGuid = new Guid("{12FA152D-A2E3-4C8D-9535-5DCD49DFCB6D}");
                foreach (Guid guid in authPlugins)
                {
                    if (pai.GetAuthenticationResult(guid).Success)
                    {
                        if (guid == SimpleUuid)
                            authSource = Packet.Acct_Authentic.RADIUS;
                        else if (guid == LocalMachinePluginGuid)
                            authSource = Packet.Acct_Authentic.Local;
                        else
                            authSource = Packet.Acct_Authentic.Remote;
                        break;
                    }
                }

                try
                {
                    lock (session)
                    {
                        session.windowsSessionId = changeDescription.SessionId;
                        session.username = username;
                        session.client.startAccounting(username, authSource);
                    }
                }
                catch (Exception e)
                {
                    m_logger.Error("Error occurred while starting accounting.", e);
                }
            }
            else if (changeDescription.Reason == System.ServiceProcess.SessionChangeReason.SessionLogoff)
            {
                lock (m_sessionManager)
                {
                    if (m_sessionManager.Keys.Contains(properties.Id))
                        session = m_sessionManager[properties.Id];
                    else
                    {
                        return;
                    }

                    m_sessionManager.Remove(properties.Id);
                }

                lock (session)
                {
                    session.disableCallbacks();
                    session.active = false;

                    if (session.terminate_cause == null)
                        session.terminate_cause = Packet.Acct_Terminate_Cause.User_Request;

                    try
                    {
                        session.client.stopAccounting(session.username, session.terminate_cause);
                    }
                    catch (RADIUSException re)
                    {
                        m_logger.DebugFormat("Unable to send accounting stop message for user {0} with ID {1}. Message: {2}", session.username, session.id, re.Message);
                    }
                }
            }
        }

        public void Configure()
        {
            Configuration conf = new Configuration();
            conf.ShowDialog();
        }

        public void Starting() 
        {
            if(m_sessionManager == null)
                m_sessionManager = new Dictionary<Guid, Session>();
        }
        public void Stopping() { }

        private RADIUSClient GetClient(string sessionId = null)
        {
            string[] servers = Regex.Split(((string)Settings.Store.GetSetting("Server", "")).Trim(), @"\s+");
            int authport = (int)Settings.Store.GetSetting("AuthPort", 1812);
            int acctport = (int)Settings.Store.GetSetting("AcctPort", 1813);
            
            string sharedKey;
            try
            {
                sharedKey = Settings.Store.GetEncryptedSetting("SharedSecret");
            }
            catch (KeyNotFoundException)
            {
                sharedKey = "";
            }

            int timeout = (int)Settings.Store.GetSetting("Timeout", 2500);
            int retry = (int)Settings.Store.GetSetting("Retry", 3);

            byte[] ipAddr = null;
            string nasIdentifier = null;
            string calledStationId = null;
            
            if((bool)Settings.Store.GetSetting("SendNASIPAddress", true))
                ipAddr = getNetworkInfo().Item1;

            if((bool)Settings.Store.GetSetting("SendNASIdentifier", true)){
                nasIdentifier = (string)Settings.Store.GetSetting("NASIdentifier", "%computername");
                nasIdentifier = nasIdentifier.Contains('%') ? replaceSymbols(nasIdentifier) : nasIdentifier;
            }

            if ((bool)Settings.Store.GetSetting("SendCalledStationID", false))
            {
                calledStationId = (string)Settings.Store.GetSetting("CalledStationID", "%macaddr");
                calledStationId = calledStationId.Contains('%') ? replaceSymbols(calledStationId) : calledStationId;
            }
 
            RADIUSClient client = new RADIUSClient(servers, authport, acctport, sharedKey, timeout, retry, sessionId, ipAddr, nasIdentifier, calledStationId);
            return client;
        }

        private string replaceSymbols(string str)
        {
            Tuple<byte[], string> networkInfo = getNetworkInfo();
            return str.Replace("%macaddr", networkInfo.Item2)
                .Replace("%ipaddr", String.Join(".", networkInfo.Item1))
                .Replace("%computername", Environment.MachineName);
        }
        
        private Tuple<byte[], string> getNetworkInfo()
        {
            string ipAddressRegex = (string)Settings.Store.GetSetting("IPSuggestion", "");
           
            byte[] ipAddr = null;
            string macAddr = null;

            foreach(NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces()){
                foreach (UnicastIPAddressInformation ipaddr in nic.GetIPProperties().UnicastAddresses)
                {
                    if (ipaddr.Address.AddressFamily == AddressFamily.InterNetwork)
                        if (String.IsNullOrEmpty(ipAddressRegex) || 
                          Regex.Match(ipaddr.Address.ToString(), ipAddressRegex).Success)
                            return Tuple.Create(ipaddr.Address.GetAddressBytes(), nic.GetPhysicalAddress().ToString());
                        else if(ipAddr == null && macAddr == null){
                            ipAddr = ipaddr.Address.GetAddressBytes();
                            macAddr = nic.GetPhysicalAddress().ToString();
                        }
                }
            }
            if (ipAddr == null) ipAddr = new byte[] { 0, 0, 0, 0 };
            if (macAddr == null) macAddr = "";
            return Tuple.Create(ipAddr, macAddr);
        }

        private void SessionTimeoutCallback(object state)
        {
            Session session = (Session)state;

            if(!session.windowsSessionId.HasValue){
                m_logger.DebugFormat("Attempting to log user {0} out due to timeout, but no windows session ID is present for ID {1}", session.username, session.id);
                return;
            }

            if (session.terminate_cause != null)
            {
                m_logger.DebugFormat("User {0} has timed out, but terminate cause #{1} has already been set for ID {2}", session.username, session.terminate_cause, session.id);
            }
            session.terminate_cause = Packet.Acct_Terminate_Cause.Session_Timeout;

            m_logger.DebugFormat("Logging off user {0} in session{1} due to session timeout.", session.username, session.windowsSessionId);
            Abstractions.WindowsApi.pInvokes.LogoffSession(session.windowsSessionId.Value);
        }

        private void SessionTerminateCallback(object state)
        {
            Session session = (Session)state;
            session.terminate_cause = Packet.Acct_Terminate_Cause.Session_Timeout;

            if (!session.windowsSessionId.HasValue)
            {
                m_logger.DebugFormat("Attempting to log user {0} out due to WISPr Session limit, but no windows session ID is present for ID {1}", session.username, session.id);
                return;
            }

            if (session.terminate_cause != null)
            {
                m_logger.DebugFormat("User {0} has reached WISPr Session limit, but terminate cause #{1} has already been set for ID {2}", session.username, session.terminate_cause, session.id);
            }
            session.terminate_cause = Packet.Acct_Terminate_Cause.Session_Timeout;

            m_logger.DebugFormat("Logging off user {0} in session{1} due to session-terminate-time.", session.username, session.windowsSessionId);
            Abstractions.WindowsApi.pInvokes.LogoffSession(session.windowsSessionId.Value);
        }

        private void InterimUpdatesCallback(object state)
        {
            Session session = (Session)state;
            lock (session)
            {
                try
                {
                    if (session.active)
                        session.client.interimUpdate(session.username);
                    else
                    {
                        session.disableCallbacks();
                    }
                }
                catch (RADIUSException e)
                {
                    m_logger.DebugFormat("Unable to send interim-update: {0}", e.Message);
                }
            }
        }
    }
}
