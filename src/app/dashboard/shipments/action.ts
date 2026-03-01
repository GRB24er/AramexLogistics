"use server";

import { prisma } from "@/constants/config/db";
import { redirect } from "next/navigation";
import { z } from "zod";
import { auth } from "~/auth";
import { revalidatePath } from "next/cache";
import transporter from "@/lib/verify-mail";

const FROM_EMAIL = "AramexLogistics <admin@aramexlogistics.org>";

const updateTrackingStatusSchema = z.object({
  shipmentId: z.string().nonempty(),
  trackingUpdateId: z.preprocess((val) => (val === null ? undefined : val), z.string().optional()),
  location: z.string().nonempty(),
  message: z.string().nonempty(),
  status: z.enum(["pending","on_hold","in_transit","delivered","returned","failed","picked_up","information_received","arrived","departed"]),
});

const STATUS_LABELS: Record<string, string> = {
  pending: "Pending", on_hold: "On Hold", in_transit: "In Transit", delivered: "Delivered",
  returned: "Returned", failed: "Delivery Failed", picked_up: "Picked Up",
  information_received: "Information Received", arrived: "Arrived at Facility", departed: "Departed Facility",
};

const STATUS_COLORS: Record<string, string> = {
  pending: "#6b7280", on_hold: "#f59e0b", in_transit: "#3b82f6", delivered: "#059669",
  returned: "#ef4444", failed: "#ef4444", picked_up: "#8b5cf6",
  information_received: "#6b7280", arrived: "#8b5cf6", departed: "#3b82f6",
};

async function sendStatusEmail(email: string, name: string, trackingNumber: string, status: string, message: string, location: string | null) {
  const statusLabel = STATUS_LABELS[status] || status;
  const statusColor = STATUS_COLORS[status] || "#059669";
  const isDelivered = status === "delivered";
  try {
    await transporter.sendMail({
      from: FROM_EMAIL, to: email,
      subject: `${isDelivered ? "✅ " : "📦 "}Shipment ${statusLabel} — ${trackingNumber} | AramexLogistics`,
      html: `<div style="font-family:'Segoe UI',Arial,sans-serif;max-width:600px;margin:0 auto;background:#fff;">
        <div style="background:linear-gradient(135deg,#0A1628 0%,#0D1F35 100%);padding:32px;text-align:center;">
          <img src="https://www.aramexlogistics.org/images/logo.png" alt="AramexLogistics" style="height:48px;margin-bottom:16px;" />
          <h1 style="color:#fff;font-size:22px;margin:0;font-weight:600;">Shipment Update</h1>
        </div>
        <div style="padding:32px;">
          <p style="color:#374151;font-size:15px;line-height:1.6;">Dear <strong>${name}</strong>,</p>
          <p style="color:#374151;font-size:15px;line-height:1.6;">There has been an update on your shipment:</p>
          <div style="text-align:center;margin:24px 0;"><span style="display:inline-block;background:${statusColor}15;color:${statusColor};border:1px solid ${statusColor}30;padding:10px 24px;border-radius:50px;font-weight:600;font-size:16px;">${statusLabel}</span></div>
          <div style="background:#f9fafb;border-radius:12px;padding:20px;margin:24px 0;">
            <table style="width:100%;border-collapse:collapse;">
              <tr><td style="padding:10px 0;color:#6b7280;font-size:14px;border-bottom:1px solid #e5e7eb;">Tracking Number</td><td style="padding:10px 0;color:#059669;font-size:14px;font-weight:600;text-align:right;border-bottom:1px solid #e5e7eb;">${trackingNumber}</td></tr>
              <tr><td style="padding:10px 0;color:#6b7280;font-size:14px;border-bottom:1px solid #e5e7eb;">Update</td><td style="padding:10px 0;color:#111827;font-size:14px;font-weight:500;text-align:right;border-bottom:1px solid #e5e7eb;">${message}</td></tr>
              ${location ? `<tr><td style="padding:10px 0;color:#6b7280;font-size:14px;">Location</td><td style="padding:10px 0;color:#111827;font-size:14px;font-weight:500;text-align:right;">${location}</td></tr>` : ""}
            </table>
          </div>
          <div style="text-align:center;margin:32px 0;"><a href="https://www.aramexlogistics.org/track" style="display:inline-block;background:#059669;color:#fff;text-decoration:none;padding:14px 32px;border-radius:8px;font-weight:600;font-size:14px;">Track Shipment</a></div>
          ${isDelivered ? `<div style="background:#f0fdf4;border:1px solid #a7f3d0;border-radius:12px;padding:20px;text-align:center;margin:24px 0;"><p style="color:#065F46;font-size:16px;font-weight:600;margin:0 0 4px 0;">✅ Delivered Successfully</p><p style="color:#059669;font-size:13px;margin:0;">Thank you for choosing AramexLogistics!</p></div>` : ""}
        </div>
        <div style="background:#f9fafb;padding:24px 32px;border-top:1px solid #e5e7eb;text-align:center;"><p style="color:#9ca3af;font-size:12px;margin:0;">&copy; ${new Date().getFullYear()} AramexLogistics | admin@aramexlogistics.org | +44 020 1412 251</p></div>
      </div>`,
    });
  } catch (error) { console.error("Failed to send status update email:", error); }
}

export async function updateTrackingStatus(formData: FormData) {
  const session = await auth();
  if (session?.user?.role !== "ADMIN") return redirect("/");

  const rawData = {
    shipmentId: formData.get("shipmentId"), trackingUpdateId: formData.get("trackingUpdateId"),
    location: formData.get("location"), message: formData.get("message"), status: formData.get("status"),
  };

  const parsedData = updateTrackingStatusSchema.safeParse(rawData);
  if (!parsedData.success) { console.error("Validation failed:", parsedData.error.flatten()); throw new Error("Invalid form data"); }

  const { shipmentId, trackingUpdateId, location, message, status } = parsedData.data;

  const shipment = await prisma.shipment.findUnique({ where: { id: shipmentId }, include: { Sender: true, recipient: true } });
  if (!shipment) throw new Error(`Shipment with id ${shipmentId} does not exist.`);

  try {
    if (trackingUpdateId && trackingUpdateId.trim() !== "") {
      await prisma.trackingUpdate.update({ where: { id: trackingUpdateId }, data: { location, message, status } });
    } else {
      await prisma.trackingUpdate.create({ data: { shipment: { connect: { id: shipmentId } }, location, message, status } });
    }

    if (status === "delivered") await prisma.shipment.update({ where: { id: shipmentId }, data: { deliveredAt: new Date() } });

    if (shipment.Sender?.email) await sendStatusEmail(shipment.Sender.email, shipment.Sender.name, shipment.trackingNumber, status, message, location);
    if (shipment.recipient?.email) await sendStatusEmail(shipment.recipient.email, shipment.recipient.name, shipment.trackingNumber, status, message, location);
  } catch (error) { console.error("Error updating tracking status:", error); throw error; }

  revalidatePath("/dashboard/shipments");
}

// ═══════════════════════════════════════════
// DELETE SHIPMENT
// ═══════════════════════════════════════════
export async function deleteShipment(shipmentId: string) {
  const session = await auth();
  if (session?.user.role !== "ADMIN") return { success: false, message: "Admin access required" };

  if (!shipmentId) return { success: false, message: "Shipment ID required" };

  try {
    const shipment = await prisma.shipment.findUnique({
      where: { id: shipmentId },
      select: { trackingNumber: true },
    });

    if (!shipment) return { success: false, message: "Shipment not found" };

    // Delete in order: tracking updates, notifications, packages, then shipment
    await prisma.trackingUpdate.deleteMany({ where: { shipmentId } });
    await prisma.notification.deleteMany({ where: { shipmentId } });
    await prisma.package.deleteMany({ where: { shipmentId } });
    await prisma.shipment.delete({ where: { id: shipmentId } });

    revalidatePath("/dashboard/shipments");
    return { success: true, message: `Shipment ${shipment.trackingNumber} deleted` };
  } catch (error: any) {
    console.error("Delete shipment error:", error);
    return { success: false, message: error.message || "Failed to delete shipment" };
  }
}

// ═══════════════════════════════════════════
// BULK DELETE SHIPMENTS
// ═══════════════════════════════════════════
export async function bulkDeleteShipments(shipmentIds: string[]) {
  const session = await auth();
  if (session?.user.role !== "ADMIN") return { success: false, message: "Admin access required" };

  if (!shipmentIds.length) return { success: false, message: "No shipments selected" };

  try {
    // Delete related records first
    await prisma.trackingUpdate.deleteMany({ where: { shipmentId: { in: shipmentIds } } });
    await prisma.notification.deleteMany({ where: { shipmentId: { in: shipmentIds } } });
    await prisma.package.deleteMany({ where: { shipmentId: { in: shipmentIds } } });
    await prisma.shipment.deleteMany({ where: { id: { in: shipmentIds } } });

    revalidatePath("/dashboard/shipments");
    return { success: true, message: `${shipmentIds.length} shipment(s) deleted` };
  } catch (error: any) {
    console.error("Bulk delete error:", error);
    return { success: false, message: error.message || "Failed to delete shipments" };
  }
}
