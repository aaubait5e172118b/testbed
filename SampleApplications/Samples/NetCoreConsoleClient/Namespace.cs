using System;
using System.Collections.Generic;
using System.Text;
using Opc.Ua;
using Opc.Ua.Client;

namespace NetCoreConsoleClient
{
    public static class Namespace
    {
        public static ReferenceDescriptionCollection BrowseRoot(Session session)
        {
            ReferenceDescriptionCollection references;
            Byte[] continuationPoint;

            references = session.FetchReferences(ObjectIds.ObjectsFolder);

            session.Browse(
                null,
                null,
                ObjectIds.ObjectsFolder,
                0u,
                BrowseDirection.Forward,
                ReferenceTypeIds.HierarchicalReferences,
                true,
                (uint)NodeClass.Variable | (uint)NodeClass.Object | (uint)NodeClass.Method,
                out continuationPoint,
                out references);

            return references;
        }

        public static ReferenceDescriptionCollection BrowseSub(Session session, ReferenceDescription reference)
        {
            ReferenceDescriptionCollection nextRefs;
            Byte[] nextCp;
            session.Browse(
                null,
                null,
                ExpandedNodeId.ToNodeId(reference.NodeId, session.NamespaceUris),
                0u,
                BrowseDirection.Forward,
                ReferenceTypeIds.HierarchicalReferences,
                true,
                (uint)NodeClass.Variable | (uint)NodeClass.Object | (uint)NodeClass.Method,
                out nextCp,
                out nextRefs);

            return nextRefs;
        }

    }
}
