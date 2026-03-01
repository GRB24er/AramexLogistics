import { auth } from "~/auth";
import { redirect } from "next/navigation";
import { getAllVaultDeposits } from "@/app/(root)/(protected)/vault/actions";
import { getClientsForVault } from "./actions";
import { AdminVaultTable } from "@/components/features/vault/admin-vault-table";
import { AdminVaultCreate } from "@/components/features/dashboard/admin-vault-create";

export default async function AdminVaultPage() {
  const session = await auth();
  if (session?.user?.role !== "ADMIN") return redirect("/");

  const [deposits, clients] = await Promise.all([
    getAllVaultDeposits(),
    getClientsForVault(),
  ]);

  return (
    <div className="p-4 lg:p-6 space-y-8">
      {/* Create New Deposit */}
      <AdminVaultCreate clients={clients} />

      {/* Existing Deposits Table */}
      <div>
        <h2 className="text-xl font-bold text-gray-900 mb-4">All Vault Deposits</h2>
        <AdminVaultTable deposits={JSON.parse(JSON.stringify(deposits))} />
      </div>
    </div>
  );
}
