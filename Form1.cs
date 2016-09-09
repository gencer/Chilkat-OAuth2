using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Oauth2
    {
    public partial class Form1 : Form
        {
        const string authorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth";
        const string tokenEndpoint = "https://www.googleapis.com/oauth2/v4/token";
        const string userInfoEndpoint = "https://www.googleapis.com/oauth2/v3/userinfo";
        const string base64Url = "base64url";

        // This is an actual client ID and secret you may use for testing.
        const string googleAppClientSecret = "kxsC3fnUZE_G4Yitso-Ikmnp";
        const string googleAppClientId = "316046393628-3b1du97rd7c2vmcpubi19os9di5n8lhu.apps.googleusercontent.com";

        // Contains data that looks like this:
        //{
        // "access_token": "ya29.Ci9ZA-Z0Q7vtnch8xxxxxxxxxxxxxxgDVOOV97-IBvTt958xxxxxx1sasw",
        // "token_type": "Bearer",
        // "expires_in": 3600,
        // "refresh_token": "1/fYjEVR-3Oq9xxxxxxxxxxxxxxLzPtlNOeQ"
        //}
        private string m_googleAccessJson = null;

        private Chilkat.Prng m_prng = null;             // This will be used for random bytes / string generation.
        private Chilkat.Crypt2 m_encoder = null;        // We'll use this for encoding/decoding

        public Form1()
            {
            InitializeComponent();

            Chilkat.Global glob = new Chilkat.Global();
            if (!glob.UnlockBundle("Anything for 30-day trial"))
                {
                MessageBox.Show("Failed to unlock Chilkat.");
                }

            m_prng = new Chilkat.Prng();
            m_encoder = new Chilkat.Crypt2();
            }

        // When we're in a background thread, we should update UI elements in the foreground thread.
        private void fgAppendToErrorLog(string s)
            {
            this.Invoke((MethodInvoker)delegate
            {
                txtErrorLog.Text += s;
            });
            }
        private void popupError(string s)
            {
            MessageBox.Show(s);
            }

        // URLs to help understand this topic:
        // https://developers.google.com/identity/protocols/OAuth2InstalledApp
        // 
        private bool oauth2_google(string scope)
            {
            // Generates state and PKCE values.
            string state = m_prng.GenRandom(32, base64Url);
            string code_verifier = m_prng.GenRandom(32, base64Url);

            Chilkat.Crypt2 crypt = new Chilkat.Crypt2();
            crypt.EncodingMode = base64Url;
            crypt.HashAlgorithm = "SHA256";
            string code_challenge = crypt.HashStringENC(code_verifier);
            const string code_challenge_method = "S256";

             //Create a Chilkat socket for listening.  Begin listening asynchronously.
            Chilkat.Socket listenSocket = new Chilkat.Socket();
            int backlog = 5;
            int listenPort = 0;
            // Passing a listenPort = 0 causes BindAndListen to find a random unused port.
            // The chosen port will be available via the ListenPort property.
            if (!listenSocket.BindAndListen(listenPort, backlog))
                {
                fgAppendToErrorLog(listenSocket.LastErrorText);
                popupError("Failed to BindAndListen");
                return false;
                }

            // Get the chosen listen port
            // This ListenPort property is available starting in Chilkat v9.5.0.59
            listenPort = listenSocket.ListenPort;

            // Creates a redirect URI using an available port on the loopback address.
            string redirect_uri = "http://127.0.0.1:" + listenPort.ToString() + "/";

             //Wait a max of 5 minutes.  The OnTaskCompleted event is called when an incoming connection
             //arrives, or when the listen failed.
            listenSocket.OnTaskCompleted += listenSocket_OnTaskCompleted;
            Chilkat.Task task = listenSocket.AcceptNextConnectionAsync(5 * 60000);
            if (task == null)
                {
                MessageBox.Show("Failed to start socket accept...");
                return false;
                }

            // Add some information that will be needed by the TaskCompleted event..
            Chilkat.JsonObject taskData = new Chilkat.JsonObject();
            taskData.AppendString("code_verifier", code_verifier);
            taskData.AppendString("redirect_uri", redirect_uri);
            task.UserData = taskData.Emit();

            // Start the task.
            task.Run();

            // Creates the OAuth 2.0 authorization request.
            Chilkat.StringBuilder sbAuthRequest = new Chilkat.StringBuilder();
            sbAuthRequest.Append(authorizationEndpoint);
            sbAuthRequest.Append("?response_type=code&scope=");
            sbAuthRequest.Append(m_encoder.EncodeString(scope,"utf-8","url"));
            sbAuthRequest.Append("&redirect_uri=");
            sbAuthRequest.Append(m_encoder.EncodeString(redirect_uri, "utf-8", "url"));
            sbAuthRequest.Append("&client_id=");
            sbAuthRequest.Append(googleAppClientId);
            sbAuthRequest.Append("&state=");
            sbAuthRequest.Append(state);
            sbAuthRequest.Append("&code_challenge=");
            sbAuthRequest.Append(code_challenge);
            sbAuthRequest.Append("&code_challenge_method=");
            sbAuthRequest.Append(code_challenge_method);

            // Here is a shorter way of building the URL in C#
            //string authorizationRequest = string.Format("{0}?response_type=code&scope={6}&redirect_uri={1}&client_id={2}&state={3}&code_challenge={4}&code_challenge_method={5}",
            //    authorizationEndpoint,  // 0
            //    System.Uri.EscapeDataString(redirect_uri), // 1
            //    googleAppClientId, // 2
            //    state, // 3
            //    code_challenge, // 4
            //    code_challenge_method, // 5
            //    System.Uri.EscapeDataString(scope)); // 6

            // Get authorization from Google account owner...
            webBrowser1.Navigate(sbAuthRequest.GetAsString());

            return true;
            }

        // This event fires in a background thread, so be careful about touching UI buttons, textboxes, etc.
        void listenSocket_OnTaskCompleted(object sender, Chilkat.TaskCompletedEventArgs args)
            {
            if (args.Task.LastMethodSuccess)
                {
                // We'll be acting as an HTTP server.
                // We'll read the incoming HTTP request and send a response.
                Chilkat.Socket httpServerSock = new Chilkat.Socket();

                // Let's inject this Chilkat.Socket object with the results of the task.
                httpServerSock.LoadTaskResult(args.Task);

                // Read the incoming start line..
                string startLine = httpServerSock.ReceiveUntilMatch("\r\n");

                // Read the HTTP request.  We'll read to the first double CRLF, which is to the end of the 
                // request header.  This should be all that is coming because the request should be a GET request (i.e. no request body).
                string requestHeader = httpServerSock.ReceiveUntilMatch("\r\n\r\n");

                // The HTTP request's startLine contains the information we need..
                // It looks like this:
                //  GET /?state=ARudjbBgI8FxgNGqEdUsv1TfYL4rAkOdDObQUT-dV8g&code=4/ovg2Tct4_Ct-BUSPnBRKyXJqsO4nGj9FNxqexxD0KK8&authuser=0&session_state=93ef25f6921934eed290ca484acb58653585ee71..bed8&prompt=consent HTTP/1.1

                // Parse the startLine by getting rid of the "GET" and "HTTP/1.1", and making it a URL that we can load into a Chilkat.HttpRequest object.
                string tempUrl = "http://www.anything.com" + startLine.Replace("GET ", "").Replace(" HTTP/1.1", "").Trim();
                Chilkat.HttpRequest tempReq = new Chilkat.HttpRequest();
                tempReq.SetFromUrl(tempUrl);

                string state = tempReq.GetParam("state");
                string code = tempReq.GetParam("code");
                string session_state = tempReq.GetParam("session_state");

                // Now send a response..
                string responseString = string.Format("<html><body><ul><li>state: " + state + "<li>code: " + code + "<li>session_state: " + session_state + "</ul></body></html>");
                httpServerSock.SendString(responseString);

                httpServerSock.Close(10);

                fgAppendToErrorLog(startLine + requestHeader + "\r\n----\r\n");

                // Now exchange the code for an access token and a refresh token.
                // (The args.Task.UserData contains the JSON we initially stashed in the Task's UserData property.)
                googleExchangeCodeForToken(code,args.Task.UserData);
                }
            else
                {
                // Failed...
                fgAppendToErrorLog(args.Task.ResultErrorText);
               }

            }

        // (for Google authorization)
        // Exchange the code for an access token and refresh token.

        // REMEMBER -- this code is running in a background thread because it is called
        // from listenSocket_OnTaskCompleted.
        private bool googleExchangeCodeForToken(string code, string taskUserData)
            {
            // The taskUserData contains JSON information.
            Chilkat.JsonObject taskData = new Chilkat.JsonObject();
            taskData.Load(taskUserData);
            string redirect_uri = taskData.StringOf("redirect_uri");
            string code_verifier = taskData.StringOf("code_verifier");

            Chilkat.Rest rest = new Chilkat.Rest();

            bool bTls = true;
            int port = 443;
            bool bAutoReconnect = true;
            bool success = rest.Connect("www.googleapis.com", port, bTls, bAutoReconnect);
            if (success != true)
                {
                fgAppendToErrorLog(rest.LastErrorText);
                return false;
                }

            success = rest.AddQueryParam("code", code);
            success = rest.AddQueryParam("client_id", googleAppClientId);
            success = rest.AddQueryParam("client_secret", googleAppClientSecret);
            success = rest.AddQueryParam("redirect_uri", redirect_uri);
            success = rest.AddQueryParam("code_verifier", code_verifier);
            success = rest.AddQueryParam("scope", "");
            success = rest.AddQueryParam("grant_type", "authorization_code");

            rest.VerboseLogging = true;
            string responseJson = rest.FullRequestFormUrlEncoded("POST", "/oauth2/v4/token");
            if (rest.LastMethodSuccess != true)
                {
                fgAppendToErrorLog(rest.LastErrorText);
                return false;
                }

            //  When successful, the response status code will equal 200.
            if (rest.ResponseStatusCode != 200)
                {
                //  Examine the request/response to see what happened.
                StringBuilder sb = new StringBuilder();
                sb.AppendLine("LastErrorText: " + rest.LastErrorText);
                sb.AppendLine("response status code = " + Convert.ToString(rest.ResponseStatusCode));
                sb.AppendLine("response status text = " + rest.ResponseStatusText);
                sb.AppendLine("response header: " + rest.ResponseHeader);
                sb.AppendLine("response body (if any): " + responseJson);
                sb.AppendLine("---");
                sb.AppendLine("LastRequestStartLine: " + rest.LastRequestStartLine);
                sb.AppendLine("LastRequestHeader: " + rest.LastRequestHeader);
                fgAppendToErrorLog(sb.ToString());
                return false;
                }

            // A successful response JSON will look like this:
            //{
            // "access_token": "ya29.Ci9ZA-Z0Q7vtnch8xxxxxxxxxxxxxxgDVOOV97-IBvTt958xxxxxx1sasw",
            // "token_type": "Bearer",
            // "expires_in": 3600,
            // "refresh_token": "1/fYjEVR-3Oq9xxxxxxxxxxxxxxLzPtlNOeQ"
            //}
            m_googleAccessJson = responseJson;

            fgAppendToErrorLog(responseJson);

            return true;
            }

        private void button1_Click(object sender, EventArgs e)
            {
            txtErrorLog.Text = "";

            string scope = comboGoogleScope.Text.Trim();
            if (scope.Length == 0)
                {
                scope = "https://www.googleapis.com/auth/drive";
                }
            oauth2_google(scope);
            }

        private string getSavedAccessToken()
            {
            if (m_googleAccessJson == null) return "";

            Chilkat.JsonObject json = new Chilkat.JsonObject();
            json.Load(m_googleAccessJson);
            return json.StringOf("access_token");
            }

        private void googleDriveListFiles()
            {
            bool success = true;

            Chilkat.AuthGoogle gAuth = new Chilkat.AuthGoogle();
            //  This is our previously obtained access token...
            gAuth.AccessToken = getSavedAccessToken();
            if (gAuth.AccessToken.Length == 0)
                {
                popupError("No previously obtained access token is available.");
                return;
                }

            Chilkat.Rest rest = new Chilkat.Rest();

            //  Connect using TLS.
            bool bAutoReconnect = true;
            success = rest.Connect("www.googleapis.com", 443, true, bAutoReconnect);

            //  Provide the authentication credentials (i.e. the access key)
            rest.SetAuthGoogle(gAuth);

            //  Add a search query parameter to only return files having names matching our criteria
            //  See https://developers.google.com/drive/v3/web/search-parameters
            // ignore = rest.AddQueryParam("q","name contains 'starfish'");
            // ignore = rest.AddQueryParam("maxResults","2");

            //  We are using the Google Drive V3 API... (not V2)
            string jsonResponse = rest.FullRequestNoBody("GET", "/drive/v3/files");
            if (rest.LastMethodSuccess != true)
                {
                fgAppendToErrorLog(rest.LastErrorText);
                popupError("REST request failed.");
                return;
                }

            // A successful JSON response looks like this:
            //{
            //  "kind": "drive#fileList",
            //  "files": [
            //    {
            //      "kind": "drive#file",
            //      "id": "0B53Q6OSTWYolenpjTEU4ekJlQUU",
            //      "name": "test",
            //      "mimeType": "application/vnd.google-apps.folder"
            //    },
            //    {
            //      "kind": "drive#file",
            //      "id": "0B53Q6OSTWYolRm4ycjZtdXhRaEE",
            //      "name": "starfish4.jpg",
            //      "mimeType": "image/jpeg"
            //    },
            //    {
            //      "kind": "drive#file",
            //      "id": "0B53Q6OSTWYolMWt2VzN0Qlo1UjA",
            //      "name": "hamlet2.xml",
            //      "mimeType": "text/xml"
            //    },
            // ...
            //    {
            //      "kind": "drive#file",
            //      "id": "0B53Q6OSTWYolc3RhcnRlcl9maWxlX2Rhc2hlclYw",
            //      "name": "Getting started",
            //      "mimeType": "application/pdf"
            //    }
            //  ]
            //}

            // Iterate over the files and show the name and mimeType of each.
            Chilkat.JsonObject json = new Chilkat.JsonObject();
            json.Load(jsonResponse);
            int numFiles = json.SizeOfArray("files");
            int i = 0;
            while (i < numFiles)
                {
                json.I = i;
                fgAppendToErrorLog("name: " + json.StringOf("files[i].name") + "\r\n");
                fgAppendToErrorLog("mimeType: " + json.StringOf("files[i].mimeType") + "\r\n");
                i++;
                }

            }


       

        private void btnListGoogleDriveFiles_Click(object sender, EventArgs e)
            {
            txtErrorLog.Text = "";
            googleDriveListFiles();
            }






        }
    }
