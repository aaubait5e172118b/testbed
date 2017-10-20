/* Copyright (c) 1996-2016, OPC Foundation. All rights reserved.
   The source code in this file is covered under a dual-license scenario:
     - RCL: for OPC Foundation members in good-standing
     - GPL V2: everybody else
   RCL license terms accompanied with this source code. See http://opcfoundation.org/License/RCL/1.00/
   GNU General Public License as published by the Free Software Foundation;
   version 2 of the License are accompanied with this source code. See http://opcfoundation.org/License/GPLv2
   This source code is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Opc.Ua;
using Opc.Ua.Client;
using System.Security.Cryptography.X509Certificates;

namespace NetCoreConsoleClient
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Console.WriteLine(".Net Core OPC UA Console Client sample");
            string endpointURL;
            if (args.Length == 0)
            {
                // use OPC UA .Net Sample server 
                endpointURL = "opc.tcp://" + Utils.GetHostName() + ":51210/UA/SampleServer";
            }
            else
            {
                endpointURL = args[0];
            }
            try
            {
                Task t = ConsoleSampleClient(endpointURL);
                t.Wait();
            }
            catch (Exception e)
            {
                Console.WriteLine("Exit due to Exception: {0}", e.Message);
            }
        }

        public static async Task ConsoleSampleClient(string endpointURL)
        {
            Console.WriteLine("1 - Create an Application Configuration.");
            Utils.SetTraceOutput(Utils.TraceOutput.DebugAndFile);
            var config = new ApplicationConfiguration()
            {
                ApplicationName = "UA Core Sample Client",
                ApplicationType = ApplicationType.Client,
                ApplicationUri = "urn:"+Utils.GetHostName()+":OPCFoundation:CoreSampleClient",
                SecurityConfiguration = new SecurityConfiguration
                {
                    ApplicationCertificate = new CertificateIdentifier
                    {
                        StoreType = "X509Store",
                        StorePath = "CurrentUser\\UA_MachineDefault",
                        SubjectName = "UA Core Sample Client"
                    },
                    TrustedPeerCertificates = new CertificateTrustList
                    {
                        StoreType = "Directory",
                        StorePath = "OPC Foundation/CertificateStores/UA Applications",
                    },
                    TrustedIssuerCertificates = new CertificateTrustList
                    {
                        StoreType = "Directory",
                        StorePath = "OPC Foundation/CertificateStores/UA Certificate Authorities",
                    },
                    RejectedCertificateStore = new CertificateTrustList
                    {
                        StoreType = "Directory",
                        StorePath = "OPC Foundation/CertificateStores/RejectedCertificates",
                    },
                    NonceLength = 32,
                    AutoAcceptUntrustedCertificates = true
                },
                TransportConfigurations = new TransportConfigurationCollection(),
                TransportQuotas = new TransportQuotas { OperationTimeout = 15000 },
                ClientConfiguration = new ClientConfiguration { DefaultSessionTimeout = 60000 }
            };

            await config.Validate(ApplicationType.Client);

            bool haveAppCertificate = config.SecurityConfiguration.ApplicationCertificate.Certificate != null;

            if (!haveAppCertificate)
            {
                Console.WriteLine("    INFO: Creating new application certificate: {0}", config.ApplicationName);

                X509Certificate2 certificate = CertificateFactory.CreateCertificate(
                    config.SecurityConfiguration.ApplicationCertificate.StoreType,
                    config.SecurityConfiguration.ApplicationCertificate.StorePath,
                    null,
                    config.ApplicationUri,
                    config.ApplicationName,
                    config.SecurityConfiguration.ApplicationCertificate.SubjectName,
                    null,
                    CertificateFactory.defaultKeySize,
                    DateTime.UtcNow - TimeSpan.FromDays(1),
                    CertificateFactory.defaultLifeTime,
                    CertificateFactory.defaultHashSize,
                    false,
                    null,
                    null
                    );

                config.SecurityConfiguration.ApplicationCertificate.Certificate = certificate;

            }

            haveAppCertificate = config.SecurityConfiguration.ApplicationCertificate.Certificate != null;

            if (haveAppCertificate)
            {
                config.ApplicationUri = Utils.GetApplicationUriFromCertificate(config.SecurityConfiguration.ApplicationCertificate.Certificate);

                if (config.SecurityConfiguration.AutoAcceptUntrustedCertificates)
                {
                    config.CertificateValidator.CertificateValidation += new CertificateValidationEventHandler(CertificateValidator_CertificateValidation);
                }
            }
            else
            {
                Console.WriteLine("    WARN: missing application certificate, using unsecure connection.");
            }

            Console.WriteLine("2 - Discover endpoints of {0}.", endpointURL);
            var selectedEndpoint = CoreClientUtils.SelectEndpoint(endpointURL, haveAppCertificate);
            Console.WriteLine("    Selected endpoint uses: {0}", 
                selectedEndpoint.SecurityPolicyUri.Substring(selectedEndpoint.SecurityPolicyUri.LastIndexOf('#') + 1));

            Console.WriteLine("3 - Create a session with OPC UA server.");
            var endpointConfiguration = EndpointConfiguration.Create(config);
            var endpoint = new ConfiguredEndpoint(null, selectedEndpoint, endpointConfiguration);
            // opretter session til server
            var session = await Session.Create(config, endpoint, false, ".Net Core OPC UA Console Client", 60000, new UserIdentity(new AnonymousIdentityToken()), null);


            Console.WriteLine("---------------------------------------------");
            


            // Browse namespace
            ReferenceDescriptionCollection rootNamespace = Namespace.BrowseRoot(session); // explores root namespace
            foreach (var reference in rootNamespace)
            {
                Console.WriteLine(reference.DisplayName);
                ReferenceDescriptionCollection subNamespace = Namespace.BrowseSub(session, reference); // explores sub namespaces
                foreach (var nextReference in subNamespace)
                    Console.WriteLine("+ " + nextReference.DisplayName);
            }

            // Read value on NodeId
            Console.WriteLine(session.ReadValue(2256)); // læser values på node id 2256 (ServerStatus) -> se namespace browse i runtime console http://documentation.unified-automation.com/uasdkhp/1.0.0/html/_l2_ua_node_ids.html

            // Create subscription on session
            await ServerSubscription.Create(session, "i = 2258", 1000);





            Console.WriteLine("Running...Press any key to exit...");
            Console.ReadKey(true); // Keep alive
            session.Close();


        }


        private static void CertificateValidator_CertificateValidation(CertificateValidator validator, CertificateValidationEventArgs e)
        {
            Console.WriteLine("Accepted Certificate: {0}", e.Certificate.Subject);
            e.Accept = (e.Error.StatusCode == StatusCodes.BadCertificateUntrusted);
        }






    }
}
