import { auth } from "~/auth";
import { redirect } from "next/navigation";
import { getAllUsers } from "./actions";
import { AdminUserPanel } from "@/components/features/dashboard/admin-user-panel";

export default async function AdminUsersPage() {
  const session = await auth();
  if (!session?.user) redirect("/");

  const users = await getAllUsers();

  return (
    <div className="p-6">
      <AdminUserPanel users={users} />
    </div>
  );
}
