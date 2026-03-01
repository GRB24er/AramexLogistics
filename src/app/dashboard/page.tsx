import { ChartAreaInteractive } from "@/components/features/dashboard/chart-area-interactive";
import { SectionCards } from "@/components/features/dashboard/section-cards";
import { redirect } from "next/navigation";
import { auth } from "~/auth";

export default async function Page() {
  const session = await auth();
  if (session?.user?.role !== "ADMIN") return redirect("/");

  return (
    <div>
      <div className="px-4 lg:px-6 py-4">
        <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
        <p className="text-sm text-gray-500">AramexLogistics Operations Overview</p>
      </div>
      <SectionCards />
      <div className="px-4 lg:px-6">
        <ChartAreaInteractive />
      </div>
    </div>
  );
}
