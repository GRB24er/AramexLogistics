// app/shipment/[id]/page.tsx
import { prisma } from "@/constants/config/db";
import { format } from "date-fns";
import { notFound, redirect } from "next/navigation";
import { TrackingUpdateForm } from "./UpdateTrackingForm";
import { auth } from "~/auth";

export default async function ShipmentDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;

  const session = await auth();
  if (session?.user?.role !== "ADMIN") {
    return redirect("/");
  }

  // Fetch the shipment along with related data
  const shipment = await prisma.shipment.findUnique({
    where: { id },
    include: {
      TrackingUpdates: true,
      packages: true,
      recipient: true,
      Sender: true,
    },
  });

  if (!shipment) {
    notFound();
  }

  // Use the last tracking update as the current status (if available)
  const currentStatus =
    shipment.TrackingUpdates.length > 0
      ? shipment.TrackingUpdates[shipment.TrackingUpdates.length - 1].status
      : "No updates";

  return (
    <div className="container mx-auto p-6 space-y-6">
      {/* Header Section */}
      <div className="bg-white shadow rounded-lg overflow-hidden">
        <div className="px-4 py-5 border-b border-gray-200 bg-gray-50">
          <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center">
            <div>
              <h1 className="text-2xl font-bold text-gray-800">
                Shipment Details
              </h1>
              <p className="text-sm text-gray-500">
                Tracking Number:{" "}
                <span className="font-medium">{shipment.trackingNumber}</span>
              </p>
            </div>
            <div className="mt-3 sm:mt-0">
              <span
                className={`inline-flex items-center px-3 py-0.5 rounded-full text-sm font-medium ${getStatusColor(
                  currentStatus
                )}`}
              >
                {currentStatus}
              </span>
            </div>
          </div>
        </div>

        {/* Shipment Information */}
        <div className="px-4 py-5">
          <dl className="grid grid-cols-1 gap-x-4 gap-y-8 sm:grid-cols-2">
            <div>
              <dt className="text-sm font-medium text-gray-500">Created At</dt>
              <dd className="mt-1 text-sm text-gray-900">
                {format(shipment.createdAt, "PPP p")}
              </dd>
            </div>
            <div>
              <dt className="text-sm font-medium text-gray-500">
                Estimated Delivery
              </dt>
              <dd className="mt-1 text-sm text-gray-900">
                {format(shipment.estimatedDelivery, "PPP p")}
              </dd>
            </div>
            <div>
              <dt className="text-sm font-medium text-gray-500">
                Payment Status
              </dt>
              <dd className="mt-1 text-sm text-gray-900">
                {shipment.isPaid ? "Paid" : "Unpaid"}
              </dd>
            </div>
            <div>
              <dt className="text-sm font-medium text-gray-500">
                Service Type
              </dt>
              <dd className="mt-1 text-sm text-gray-900">
                {shipment.serviceType}
              </dd>
            </div>
            <div className="sm:col-span-2">
              <dt className="text-sm font-medium text-gray-500">
                Origin Address
              </dt>
              <dd className="mt-1 text-sm text-gray-900">
                {shipment.originAddress}, {shipment.originCity},{" "}
                {shipment.originState} {shipment.originPostalCode},{" "}
                {shipment.originCountry}
              </dd>
            </div>
            <div className="sm:col-span-2">
              <dt className="text-sm font-medium text-gray-500">
                Destination Address
              </dt>
              <dd className="mt-1 text-sm text-gray-900">
                {shipment.destinationAddress}, {shipment.destinationCity},{" "}
                {shipment.destinationState} {shipment.destinationPostalCode},{" "}
                {shipment.destinationCountry}
              </dd>
            </div>
            <div>
              <dt className="text-sm font-medium text-gray-500">Sender</dt>
              <dd className="mt-1 text-sm text-gray-900">
                {shipment.Sender?.name || "N/A"}
              </dd>
            </div>
            {shipment.Sender?.email && (
              <div>
                <dt className="text-sm font-medium text-gray-500">
                  Sender Email
                </dt>
                <dd className="mt-1 text-sm text-gray-900">
                  {shipment.Sender.email}
                </dd>
              </div>
            )}
            <div>
              <dt className="text-sm font-medium text-gray-500">Recipient</dt>
              <dd className="mt-1 text-sm text-gray-900">
                {shipment.recipient.name}
              </dd>
            </div>
          </dl>
        </div>

        {/* Package Details */}
        <div className="px-4 py-5 border-t border-gray-200">
          <h2 className="text-xl font-semibold text-gray-800">
            Package Details
          </h2>
          <div className="mt-4 space-y-4">
            {shipment.packages.map((pkg) => (
              <div key={pkg.id} className="border p-4 rounded-lg">
                <p className="text-sm text-gray-500">
                  <strong>Package Type:</strong> {pkg.packageType}
                </p>
                <p className="text-sm text-gray-500">
                  <strong>Dimensions:</strong> {pkg.height} x {pkg.length} x{" "}
                  {pkg.width} cm
                </p>
                <p className="text-sm text-gray-500">
                  <strong>Weight:</strong> {pkg.weight} kg
                </p>
                <p className="text-sm text-gray-500">
                  <strong>Declared Value:</strong> ${pkg.declaredValue || 0}
                </p>
                <p className="text-sm text-gray-500">
                  <strong>Description:</strong> {pkg.description}
                </p>
              </div>
            ))}
          </div>
        </div>

        {/* Tracking Timeline */}
        <div className="px-4 py-5 border-t border-gray-200">
          <h2 className="text-xl font-semibold text-gray-800">
            Tracking Timeline
          </h2>
          <ul className="mt-4 space-y-4">
            {shipment.TrackingUpdates.map((update) => (
              <li key={update.id} className="border-b pb-2">
                <p className="text-sm font-medium text-gray-900">
                  {update.status}
                </p>
                <p className="text-sm text-gray-500">
                  {format(update.timestamp, "PPP p")}
                </p>
                <p className="text-sm text-gray-500">{update.message}</p>
                {update.location && (
                  <p className="text-sm text-gray-500">
                    <strong>Location:</strong> {update.location}
                  </p>
                )}
              </li>
            ))}
          </ul>
        </div>

        {/* Tracking Update Form using Server Action */}
        <div className="px-4 py-5 border-t border-gray-200">
          <TrackingUpdateForm shipmentId={shipment.id} />
        </div>
      </div>
    </div>
  );
}

// Helper function to determine status color styles
function getStatusColor(status: string | null): string {
  switch (status?.toLowerCase()) {
    case "delivered":
      return "bg-green-100 text-green-800";
    case "in_transit":
      return "bg-blue-100 text-blue-800";
    case "arrived":
      return "bg-purple-100 text-purple-800";
    case "departed":
      return "bg-indigo-100 text-indigo-800";
    case "picked_up":
      return "bg-yellow-100 text-yellow-800";
    case "information_received":
      return "bg-gray-100 text-gray-800";
    case "failed":
      return "bg-red-100 text-red-800";
    default:
      return "bg-gray-100 text-gray-800";
  }
}
