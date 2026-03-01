import { auth } from "~/auth";
import { redirect } from "next/navigation";
import { getShipmentsForDocuments } from "./actions";
import { AdminDocumentPanel } from "@/components/features/dashboard/admin-document-panel";

export default async function AdminDocumentsPage() {
  const session = await auth();
  if (!session?.user) redirect("/");

  const shipments = await getShipmentsForDocuments();

  return (
    <div className="p-6">
      <AdminDocumentPanel shipments={shipments} />
    </div>
  );
}
