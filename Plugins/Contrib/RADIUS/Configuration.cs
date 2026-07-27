using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;

using OpenCredential.Shared.Settings;

namespace OpenCredential.Plugin.RADIUS
{
    public partial class Configuration : Form
    {
        dynamic m_settings = new OpenCredentialDynamicSettings(RADIUSPlugin.SimpleUuid);

        public Configuration()
        {
            InitializeComponent();
            secretTB.UseSystemPasswordChar = true;
            sendNasIdentifierCB.CheckedChanged += checkboxModifyInputs;
            sendCalledStationCB.CheckedChanged += checkboxModifyInputs;
            enableAuthCB.CheckedChanged += checkboxModifyInputs;
            enableAcctCB.CheckedChanged += checkboxModifyInputs;
            sendInterimUpdatesCB.CheckedChanged += checkboxModifyInputs;
            
            // New event handlers for authorization and gateway:
            enableAuthzCB.CheckedChanged += checkboxModifyInputs;
            enableGatewayCB.CheckedChanged += checkboxModifyInputs;

            load();
        }

        private bool save()
        {
            int authport = 0;
            int acctport = 0;
            int timeout = 0;
            int retry = 0;
            int interim_time = 0;
            
            try
            {
                authport = Convert.ToInt32(authPortTB.Text.Trim());
                acctport = Convert.ToInt32(acctPortTB.Text.Trim());
                timeout = (int)(1000 * Convert.ToDouble(timeoutTB.Text.Trim()));
                retry = Convert.ToInt32(retryTB.Text.Trim());
                interim_time = Convert.ToInt32(forceInterimUpdTB.Text.Trim());
                
                if (authport <= 0 || acctport <= 0 || timeout <= 0 || retry <= 0 || interim_time <= 0)
                    throw new FormatException("Ports, Retry, Timeout and interval values must be values greater than 0");
            }
            catch (FormatException)
            {
                MessageBox.Show("Port and Timeout values must be numbers greater than 0.");
                return false;
            }

            if (enableAuthCB.Checked)
            {
                if (!sendNasIpAddrCB.Checked && !sendNasIdentifierCB.Checked)
                {
                    MessageBox.Show("Send NAS IP Address or Send NAS Identifier must be checked under Authentication Options");
                    return false;
                }

                if (sendNasIdentifierCB.Checked && String.IsNullOrEmpty(sendNasIdentifierTB.Text.Trim()))
                {
                    MessageBox.Show("NAS Identifier can not be blank if the option is enabled.");
                    return false;
                }

                if (sendCalledStationCB.Checked && String.IsNullOrEmpty(sendCalledStationTB.Text.Trim()))
                {
                    MessageBox.Show("Called-Station-ID can not be blank if the option is enabled.");
                    return false;
                }
            }

            if (enableGatewayCB.Checked && String.IsNullOrEmpty(gatewayLocalGroupTB.Text.Trim()))
            {
                MessageBox.Show("Gateway Local Group cannot be blank if the option is enabled.");
                return false;
            }

            Settings.Store.EnableAuth = enableAuthCB.Checked;
            Settings.Store.EnableAcct = enableAcctCB.Checked;

            // Authorization & Gateway Settings
            Settings.Store.EnableAuthz = enableAuthzCB.Checked;
            Settings.Store.AuthzRequireSuccess = authzRequireSuccessCB.Checked;
            Settings.Store.EnableGateway = enableGatewayCB.Checked;
            Settings.Store.GatewayLocalGroup = gatewayLocalGroupTB.Text.Trim();

            Settings.Store.Server = serverTB.Text.Trim();
            Settings.Store.AuthPort = authport;
            Settings.Store.AcctPort = acctport;
            Settings.Store.SetEncryptedSetting("SharedSecret", secretTB.Text);
            Settings.Store.Timeout = timeout;
            Settings.Store.Retry = retry;

            Settings.Store.SendNASIPAddress = sendNasIpAddrCB.Checked;
            Settings.Store.SendNASIdentifier = sendNasIdentifierCB.Checked;
            Settings.Store.NASIdentifier = sendNasIdentifierTB.Text.Trim();
            Settings.Store.SendCalledStationID = sendCalledStationCB.Checked;
            Settings.Store.CalledStationID = sendCalledStationTB.Text.Trim();

            Settings.Store.AcctingForAllUsers = acctingForAllUsersCB.Checked;
            Settings.Store.SendInterimUpdates = sendInterimUpdatesCB.Checked;
            Settings.Store.ForceInterimUpdates = forceInterimUpdCB.Checked;
            Settings.Store.InterimUpdateTime = interim_time;
               
            Settings.Store.AllowSessionTimeout = sessionTimeoutCB.Checked;
            Settings.Store.WisprSessionTerminate = wisprTimeoutCB.Checked;
            
            Settings.Store.UseModifiedName = useModifiedNameCB.Checked;
            Settings.Store.IPSuggestion = ipAddrSuggestionTB.Text.Trim();

            return true;
        }

        private void load()
        {
            enableAuthCB.Checked = (bool)Settings.Store.GetSetting("EnableAuth", true);
            enableAcctCB.Checked = (bool)Settings.Store.GetSetting("EnableAcct", false);

            // Safe Authorization & Gateway Settings Loading
            enableAuthzCB.Checked = (bool)Settings.Store.GetSetting("EnableAuthz", true);
            authzRequireSuccessCB.Checked = (bool)Settings.Store.GetSetting("AuthzRequireSuccess", true);
            enableGatewayCB.Checked = (bool)Settings.Store.GetSetting("EnableGateway", true);
            gatewayLocalGroupTB.Text = (string)Settings.Store.GetSetting("GatewayLocalGroup", "Users");

            serverTB.Text = (string)Settings.Store.GetSetting("Server", "");
            authPortTB.Text = String.Format("{0}", (int)Settings.Store.GetSetting("AuthPort", 1812));
            acctPortTB.Text = String.Format("{0}", (int)Settings.Store.GetSetting("AcctPort", 1813));

            try
            {
                secretTB.Text = Settings.Store.GetEncryptedSetting("SharedSecret");
            }
            catch (KeyNotFoundException)
            {
                secretTB.Text = "";
            }

            timeoutTB.Text = String.Format("{0:0.00}", ((int)Settings.Store.GetSetting("Timeout", 2500)) / 1000.0 );
            retryTB.Text = String.Format("{0}", (int)Settings.Store.GetSetting("Retry", 3));

            sendNasIpAddrCB.Checked = (bool)Settings.Store.GetSetting("SendNASIPAddress", true);
            sendNasIdentifierCB.Checked = (bool)Settings.Store.GetSetting("SendNASIdentifier", true);
            sendNasIdentifierTB.Text = (string)Settings.Store.GetSetting("NASIdentifier", "%computername");
            sendCalledStationCB.Checked = (bool)Settings.Store.GetSetting("SendCalledStationID", false);
            sendCalledStationTB.Text = (string)Settings.Store.GetSetting("CalledStationID", "%macaddr");

            acctingForAllUsersCB.Checked = (bool)Settings.Store.GetSetting("AcctingForAllUsers", false);
            sendInterimUpdatesCB.Checked = (bool)Settings.Store.GetSetting("SendInterimUpdates", false);
            forceInterimUpdCB.Checked = (bool)Settings.Store.GetSetting("ForceInterimUpdates", false);
            forceInterimUpdTB.Text = String.Format("{0}", (int)Settings.Store.GetSetting("InterimUpdateTime", 900));

            sessionTimeoutCB.Checked = (bool)Settings.Store.GetSetting("AllowSessionTimeout", false);
            wisprTimeoutCB.Checked = (bool)Settings.Store.GetSetting("WisprSessionTerminate", false);

            ipAddrSuggestionTB.Text = (string)Settings.Store.GetSetting("IPSuggestion", "");
            useModifiedNameCB.Checked = (bool)Settings.Store.GetSetting("UseModifiedName", false);
        }

        private void checkboxModifyInputs(object sender, EventArgs e)
        {
            // Server Settings
            authPortTB.Enabled = enableAuthCB.Checked;
            acctPortTB.Enabled = enableAcctCB.Checked;
            
            // Authentication options:
            authGB.Enabled = enableAuthCB.Checked;
            sendNasIdentifierTB.Enabled = sendNasIdentifierCB.Checked;
            sendCalledStationTB.Enabled = sendCalledStationCB.Checked;

            // Accounting options
            acctGB.Enabled = enableAcctCB.Checked;
            forceInterimUpdCB.Enabled = sendInterimUpdatesCB.Checked;
            forceInterimUpdTB.Enabled = forceInterimUpdCB.Enabled;
            forceInterimUpdLbl.Enabled = forceInterimUpdCB.Enabled;

            // Authorization & Gateway options
            authzRequireSuccessCB.Enabled = enableAuthzCB.Checked;
            gatewayLocalGroupTB.Enabled = enableGatewayCB.Checked;
        }

        private void btnOk_Click(object sender, EventArgs e)
        {
            this.DialogResult = System.Windows.Forms.DialogResult.OK;

            if(save())
                this.Close();
        }

        private void btnCancel_Click(object sender, EventArgs e)
        {
            this.DialogResult = System.Windows.Forms.DialogResult.Cancel;
            this.Close();
        }

        private void showSecretChanged(object sender, EventArgs e)
        {
            secretTB.UseSystemPasswordChar = !showSecretCB.Checked;
        }

        private void Configuration_Load(object sender, EventArgs e)
        {
        }
    }
}
