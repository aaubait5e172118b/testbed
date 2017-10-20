using System;
using System.Collections.Generic;
using System.Text;
using Opc.Ua;
using Opc.Ua.Client;
using System.Threading.Tasks;

namespace NetCoreConsoleClient
{
    public static class ServerSubscription
    {

        public static async Task Create(Session session, string nodeId, int interval = 5000)
        {
            Subscription subscription = new Subscription(session.DefaultSubscription) { PublishingInterval = interval };

            Console.WriteLine("Subscription created");
            var list = new List<MonitoredItem> {
               new MonitoredItem(subscription.DefaultItem)
               {
                   DisplayName = "ServerStatusCurrentTime", StartNodeId = nodeId
               }
           };

            list.ForEach(i => i.Notification += OnNotification);
            subscription.AddItems(list);

            session.AddSubscription(subscription);
            subscription.Create();


        }

        private static void OnNotification(MonitoredItem item, MonitoredItemNotificationEventArgs e)
        {
            foreach (var value in item.DequeueValues())
            {
                Console.WriteLine("{0}: {1}, {2}, {3}", item.DisplayName, value.Value, value.SourceTimestamp, value.StatusCode);
            }
        }
    }
}
