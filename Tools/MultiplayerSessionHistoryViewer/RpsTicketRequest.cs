//-----------------------------------------------------------------------
// <copyright file="RpsTicketRequest.cs" company="Microsoft">
//     Copyright (c) Microsoft. All rights reserved.
//     Internal use only.
// </copyright>
//-----------------------------------------------------------------------

using System;
using System.Configuration;
using System.Threading;
using System.Web;
using System.Windows.Forms;

namespace SessionHistoryViewer
{
    public class RpsTicketRequest
    {
        static readonly string ClientId = ConfigurationManager.AppSettings["ClientId"];
        static readonly string LiveHost = ConfigurationManager.AppSettings["MsaHost"];
        static readonly string Scope = ConfigurationManager.AppSettings["Scope"];

        private AutoResetEvent evt = new AutoResetEvent(false);
        public string RpsTicket { get; set; }

        public void GetToken()
        {
            var th = new Thread(() =>
            {
                Form form = new Form()
                {
                    Width = 453,
                    Height = 529,

                };
                form.AutoSize = true;
                form.FormClosed += form_FormClosed;
                WebBrowser wb = new WebBrowser();
                wb.Dock = DockStyle.Fill;
                wb.DocumentCompleted += wb_DocumentCompleted;
                wb.Navigated += wb_Navigated;
                wb.Navigate(
                    String.Format(
                    "https://login.{0}/oauth20_authorize.srf?client_id={1}&scope={2}&response_type=token&redirect_uri=https://login.{0}/oauth20_desktop.srf",
                    LiveHost, ClientId, Scope));
                form.Controls.Add(wb);
                Application.Run(form);
                wb.Show();
            });

            th.SetApartmentState(ApartmentState.STA);
            th.Start();
        }

        public void SignOut()
        {
            var th = new Thread(() =>
            {
                Form form = new Form()
                {
                    Width = 453,
                    Height = 529,

                };
                form.AutoSize = true;
                form.FormClosed += form_FormClosed;
                WebBrowser wb = new WebBrowser();
                wb.Dock = DockStyle.Fill;
                wb.DocumentCompleted += wb_DocumentCompleted;
                wb.Navigated += wb_Navigated;
                wb.Navigate(
                    String.Format(
                    "https://login.{0}/oauth20_logout.srf?client_id={1}&redirect_uri=https://login.{0}/oauth20_desktop.srf",
                    LiveHost, ClientId, Scope));
                form.Controls.Add(wb);
                Application.Run(form);
                wb.Show();
            });

            th.SetApartmentState(ApartmentState.STA);
            th.Start();
        }

        private void form_FormClosed(object sender, FormClosedEventArgs e)
        {
            evt.Set();
            Application.ExitThread();
        }


        void wb_Navigated(object sender, WebBrowserNavigatedEventArgs e)
        {


            if (e.Url.AbsolutePath == "/oauth20_desktop.srf")
            {
                // get the token from here
                this.RpsTicket = HttpUtility.ParseQueryString(e.Url.Fragment)["#access_token"];
                evt.Set();
                Application.ExitThread();
            }
        }

        public void Wait()
        {
            evt.WaitOne();

        }

        static void wb_DocumentCompleted(object sender, WebBrowserDocumentCompletedEventArgs e)
        {
        }
    }
}