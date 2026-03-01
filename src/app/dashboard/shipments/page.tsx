import { ShipmentsPage } from "@/components/features/shipment/shipment.page";
import { prisma } from "@/constants/config/db";
import { redirect } from "next/navigation";
import { auth } from "~/auth";
import { format } from "date-fns";

// Map database status to frontend status
// Map database status to frontend status
function mapStatus(trackingUpdates: { status: string | null }[]): "Delivered" | "In_transit" | "Proccessing" | "On_hold" {
  if (trackingUpdates.length === 0) return "Proccessing";
  
  const lastUpdate = trackingUpdates[trackingUpdates.length - 1];
  if (!lastUpdate.status) return "Proccessing";
  
  const lastStatus = lastUpdate.status.toLowerCase();
  
  if (lastStatus === "delivered") return "Delivered";
  if (lastStatus === "in_transit" || lastStatus === "in-transit") return "In_transit";
  if (lastStatus === "on_hold" || lastStatus === "failed") return "On_hold";
  if (lastStatus === "picked_up" || lastStatus === "departed" || lastStatus === "arrived") return "In_transit";
  if (lastStatus === "information_received") return "Proccessing";
  
  return "Proccessing";
}
const ShipmentsPageWrapper = async () => {
  const session = await auth();
  if (!session?.user) {
    return redirect("/");
  }

  const data = await prisma.shipment.findMany({
    include: { 
      TrackingUpdates: {
        orderBy: {
          timestamp: "asc",
        },
      },
      recipient: true,
      packages: true,
    },
    orderBy: {
      createdAt: "desc",
    },
  });

  console.log("SHIPMENTS COUNT:", data.length);

  // Transform Prisma data to match frontend Shipment type
  const shipments = data.map((shipment) => {
    // Calculate total items (sum of pieces) and weight from packages
    const totalItems = shipment.packages.reduce((sum, pkg) => sum + pkg.pieces, 0);
    const totalWeight = shipment.packages.reduce((sum, pkg) => sum + pkg.weight, 0);
    const totalValue = shipment.packages.reduce((sum, pkg) => sum + (pkg.declaredValue || 0), 0);

    // Find delivered update if exists
    const deliveredUpdate = shipment.TrackingUpdates.find(
      (u) => u.status?.toLowerCase() === "delivered"
    );

    return {
      id: shipment.id,
      tracking_number: shipment.trackingNumber,
      status: mapStatus(shipment.TrackingUpdates),
      origin: `${shipment.originCity}, ${shipment.originCountry}`,
      destination: `${shipment.destinationCity}, ${shipment.destinationCountry}`,
      date: format(shipment.createdAt, "MMM dd, yyyy"),
      eta: format(shipment.estimatedDelivery, "MMM dd, yyyy"),
      delivered: deliveredUpdate 
        ? format(deliveredUpdate.timestamp, "MMM dd, yyyy") 
        : shipment.deliveredAt 
          ? format(shipment.deliveredAt, "MMM dd, yyyy")
          : null,
      items: totalItems || shipment.packages.length,
      weight: `${totalWeight} kg`,
      type: shipment.serviceType,
      value: `$${totalValue.toFixed(2)}`,
      originPostalCode: shipment.originPostalCode,
      destinationPostalCode: shipment.destinationPostalCode,
      lastUpdate: shipment.TrackingUpdates.length > 0
        ? format(
            shipment.TrackingUpdates[shipment.TrackingUpdates.length - 1].timestamp,
            "MMM dd, yyyy HH:mm"
          )
        : "No updates",
      recipient: {
        name: shipment.recipient.name,
        imageUrl: null,
      },
    };
  });

  return (
    <div>
      <ShipmentsPage shipments={shipments} />
    </div>
  );
};

export default ShipmentsPageWrapper;