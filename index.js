import express from "express";
import cors from "cors";
import "dotenv/config";
import Stripe from "stripe";
import { MongoClient, ObjectId } from "mongodb";
import { jwtVerify } from "jose";

const app = express();
const port = process.env.PORT || 5000;
const CLIENT_URL = process.env.CLIENT_URL || "http://localhost:3000";
const FREE_SERVICE_LIMIT = 3;

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || "");
const client = new MongoClient(process.env.MONGODB_URI);
let db;

// ---------- Helpers --------------
const escapeRegex = (s = "") => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const toObjectId = (id) => (ObjectId.isValid(id) ? new ObjectId(id) : null);
const col = (name) => db.collection(name);

async function findUser(id) {
  const conditions = [{ _id: id }];
  if (ObjectId.isValid(id)) conditions.push({ _id: new ObjectId(id) });
  return col("user").findOne({ $or: conditions });
}

const isPremium = (user) =>
  user?.subscriptionPlan === "premium" &&
  user?.subscriptionExpiresAt &&
  new Date(user.subscriptionExpiresAt) > new Date();

const fail = (res, status, message, extra = {}) =>
  res.status(status).send({ success: false, message, ...extra });

const serverError = (res, label, error, message) => {
  console.error(label, error);
  return fail(res, 500, message);
};

// ---------- CORS ----------
app.use(
  cors({
    origin: [
      "http://localhost:3000",
      "https://wed-plan-client-site.vercel.app",
    ],
    methods: ["GET", "POST", "PATCH", "DELETE", "PUT"],
    credentials: true,
  }),
);
// ---------- DB connection ----------
async function ensureDb(req, res, next) {
  try {
    if (!db) {
      await client.connect();
      db = client.db(process.env.DB_NAME || "wedplan");
    }
    next();
  } catch (error) {
    console.error("MongoDB Connection Failed:", error);
    fail(res, 500, "Database connection failed!");
  }
}
app.use(ensureDb);

// ---------- Stripe Webhook (raw body, express.json er AGE) ----------
function periodEndOf(subscription) {
  const seconds =
    subscription.current_period_end ??
    subscription.items?.data?.[0]?.current_period_end;
  return seconds
    ? new Date(seconds * 1000)
    : new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
}

app.post(
  "/webhooks/stripe",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    let event;
    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        req.headers["stripe-signature"],
        process.env.STRIPE_WEBHOOK_SECRET,
      );
    } catch (error) {
      console.error("Webhook signature failed:", error.message);
      return res.status(400).send("Webhook signature verification failed");
    }

    try {
      const users = col("user");
      const transactions = col("transactions");

      switch (event.type) {
        case "checkout.session.completed": {
          const session = event.data.object;
          if (session.payment_status !== "paid") break;

          const vendorId = session.metadata?.vendorId;
          const subscriptionId = session.subscription;
          const subscription =
            await stripe.subscriptions.retrieve(subscriptionId);
          const expiresAt = periodEndOf(subscription);

          await transactions.updateOne(
            { stripeSessionId: session.id },
            {
              $set: {
                status: "paid",
                stripeSubscriptionId: subscriptionId,
                amount: (session.amount_total || 0) / 100,
                currency: session.currency,
                paidAt: new Date(),
              },
              $setOnInsert: {
                vendorId,
                plan: "premium",
                stripeSessionId: session.id,
                createdAt: new Date(),
              },
            },
            { upsert: true },
          );

          const vendor = await findUser(vendorId);
          if (vendor) {
            await users.updateOne(
              { _id: vendor._id },
              {
                $set: {
                  subscriptionPlan: "premium",
                  subscriptionExpiresAt: expiresAt,
                  stripeSubscriptionId: subscriptionId,
                },
              },
            );
          }
          break;
        }

        case "checkout.session.expired": {
          await transactions.updateOne(
            { stripeSessionId: event.data.object.id, status: "pending" },
            { $set: { status: "expired" } },
          );
          break;
        }

        case "customer.subscription.updated": {
          const subscription = event.data.object;
          if (["active", "trialing"].includes(subscription.status)) {
            await users.updateOne(
              { stripeSubscriptionId: subscription.id },
              {
                $set: {
                  subscriptionPlan: "premium",
                  subscriptionExpiresAt: periodEndOf(subscription),
                },
              },
            );
          }
          break;
        }

        case "customer.subscription.deleted": {
          await users.updateOne(
            { stripeSubscriptionId: event.data.object.id },
            {
              $set: { subscriptionPlan: "free", subscriptionExpiresAt: null },
              $unset: { stripeSubscriptionId: "" },
            },
          );
          break;
        }

        default:
          break;
      }

      res.status(200).send({ received: true });
    } catch (error) {
      console.error("Webhook handler error:", error);
      res.status(500).send({ received: false });
    }
  },
);

app.use(express.json());

// ---------- Auth Middleware ----------
async function verifyToken(req, res, next) {
  try {
    const authorization = req.headers.authorization;
    if (!authorization?.startsWith("Bearer ")) {
      return fail(res, 401, "Unauthorized! Token is required.");
    }

    const secret = process.env.JWT_SECRET;
    if (!secret) throw new Error("JWT_SECRET is missing!");

    const { payload } = await jwtVerify(
      authorization.split(" ")[1],
      new TextEncoder().encode(secret),
      {
        issuer: "wedplan-client",
        audience: "wedplan-api",
        algorithms: ["HS256"],
      },
    );

    if (!payload.sub) return fail(res, 401, "Invalid user information!");

    // Token er role e bharosha nai: asol user DB theke ana hocche
    const user = await findUser(payload.sub);
    if (!user) return fail(res, 401, "User not found!");
    if (user.isBlocked) {
      return fail(res, 403, "Your account has been blocked!");
    }

    const role = user.role || "customer";
    if (!["customer", "vendor", "admin"].includes(role)) {
      return fail(res, 401, "Invalid user role!");
    }

    req.user = { id: String(user._id), email: user.email, role, doc: user };
    next();
  } catch (error) {
    return fail(res, 401, "Invalid or expired token!");
  }
}

function verifyRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return fail(res, 403, "Forbidden! You don't have permission.");
    }
    next();
  };
}

const vendorOnly = [verifyToken, verifyRole("vendor")];
const customerOnly = [verifyToken, verifyRole("customer")];
const adminOnly = [verifyToken, verifyRole("admin")];

// ---------- Basic ----------
app.get("/", (req, res) => res.send("WedPlan Server is Running!"));

app.get("/test-db", async (req, res) => {
  try {
    await db.command({ ping: 1 });
    res.send({ success: true, message: "Database Connected Successfully!" });
  } catch {
    fail(res, 500, "Database Connection Failed!");
  }
});

app.post("/contact", async (req, res) => {
  try {
    const { name, email, subject, message } = req.body;
    if (!name || !email || !subject || !message) {
      return fail(res, 400, "All fields are required!");
    }
    const result = await col("contacts").insertOne({
      name,
      email,
      subject,
      message,
      createdAt: new Date(),
    });
    res.status(201).send({
      success: true,
      message: "Message sent successfully!",
      insertedId: result.insertedId,
    });
  } catch (error) {
    serverError(res, "Contact API Error:", error, "Failed to send message!");
  }
});

// ---------- Current user / Profile ----------
app.get("/me", verifyToken, (req, res) => {
  const u = req.user.doc;
  res.send({
    success: true,
    user: {
      id: String(u._id),
      name: u.name,
      email: u.email,
      image: u.image || "",
      role: u.role,
      businessName: u.businessName || "",
      phone: u.phone || "",
      subscriptionPlan: isPremium(u) ? "premium" : "free",
      subscriptionExpiresAt: u.subscriptionExpiresAt || null,
    },
  });
});

// Shudhu safe field: role / subscription / isBlocked kokhono accept kora hoy na
app.patch("/me", verifyToken, async (req, res) => {
  try {
    const { name, image, phone, businessName } = req.body;
    const update = {};

    if (name !== undefined) {
      if (!String(name).trim()) return fail(res, 400, "Name cannot be empty!");
      update.name = String(name).trim();
    }
    if (image !== undefined) update.image = String(image);
    if (phone !== undefined) update.phone = String(phone).trim();
    if (businessName !== undefined && req.user.role === "vendor") {
      update.businessName = String(businessName).trim();
    }

    if (Object.keys(update).length === 0) {
      return fail(res, 400, "Nothing to update!");
    }

    update.updatedAt = new Date();
    await col("user").updateOne({ _id: req.user.doc._id }, { $set: update });

    if (req.user.role === "vendor") {
      const sync = {};
      if (update.name) sync.vendorName = update.name;
      if (update.businessName !== undefined)
        sync.vendorBusinessName = update.businessName;
      if (update.image !== undefined) sync.vendorImage = update.image;
      if (Object.keys(sync).length) {
        await col("services").updateMany(
          { vendorId: req.user.id },
          { $set: sync },
        );
      }
    }

    res.send({ success: true, message: "Profile updated successfully!" });
  } catch (error) {
    serverError(
      res,
      "Update Profile Error:",
      error,
      "Failed to update profile!",
    );
  }
});

// ---------- Public Services ----------
const PUBLIC_FILTER = { status: "approved", isActive: { $ne: false } };

app.get("/services", async (req, res) => {
  try {
    const {
      search,
      category,
      location,
      sort,
      page = 1,
      limit = 12,
    } = req.query;
    const filter = { ...PUBLIC_FILTER };

    if (search)
      filter.serviceName = { $regex: escapeRegex(search), $options: "i" };
    if (category) filter.category = category;
    if (location)
      filter.location = { $regex: escapeRegex(location), $options: "i" };

    let sortQuery = { createdAt: -1 };
    if (sort === "price_asc") sortQuery = { price: 1 };
    if (sort === "price_desc") sortQuery = { price: -1 };

    const pageNum = Math.max(Number(page) || 1, 1);
    const limitNum = Math.min(Math.max(Number(limit) || 12, 1), 50);

    const [services, total] = await Promise.all([
      col("services")
        .find(filter)
        .sort(sortQuery)
        .skip((pageNum - 1) * limitNum)
        .limit(limitNum)
        .toArray(),
      col("services").countDocuments(filter),
    ]);

    res.send({
      success: true,
      services,
      total,
      page: pageNum,
      totalPages: Math.ceil(total / limitNum),
    });
  } catch (error) {
    serverError(res, "Services API Error:", error, "Failed to fetch services!");
  }
});

app.get("/services/meta/filters", async (req, res) => {
  try {
    const [categories, locations] = await Promise.all([
      col("services").distinct("category", PUBLIC_FILTER),
      col("services").distinct("location", PUBLIC_FILTER),
    ]);
    res.send({ success: true, categories, locations });
  } catch (error) {
    serverError(res, "Filters Error:", error, "Failed to fetch filters!");
  }
});

app.get("/services/:id", async (req, res) => {
  try {
    const _id = toObjectId(req.params.id);
    if (!_id) return fail(res, 400, "Invalid Service ID!");

    const service = await col("services").findOne({ _id, ...PUBLIC_FILTER });
    if (!service) return fail(res, 404, "Service not found!");

    res.send({ success: true, service });
  } catch (error) {
    serverError(
      res,
      "Single Service Error:",
      error,
      "Failed to fetch service details!",
    );
  }
});

// ---------- Vendor: Services ----------
async function activeServiceCount(vendorId, excludeId) {
  const filter = { vendorId, isActive: true, status: { $ne: "rejected" } };
  if (excludeId) filter._id = { $ne: excludeId };
  return col("services").countDocuments(filter);
}

function validateServiceBody(body) {
  const { serviceName, category, description, price, location, images } = body;
  if (
    !serviceName?.trim() ||
    !category ||
    !description?.trim() ||
    !location?.trim()
  ) {
    return "Please fill in all required fields!";
  }
  if (price === undefined || isNaN(Number(price)) || Number(price) < 0) {
    return "Price must be a valid positive number!";
  }
  if (!Array.isArray(images) || images.length === 0) {
    return "At least one service image is required!";
  }
  return null;
}

app.post("/services", ...vendorOnly, async (req, res) => {
  try {
    const error = validateServiceBody(req.body);
    if (error) return fail(res, 400, error);

    const vendor = req.user.doc;
    if (!isPremium(vendor)) {
      const count = await activeServiceCount(req.user.id);
      if (count >= FREE_SERVICE_LIMIT) {
        return fail(
          res,
          403,
          "Free plan limit reached! Upgrade to Premium to publish more services.",
          { code: "LIMIT_REACHED" },
        );
      }
    }

    const { serviceName, category, description, price, location, images } =
      req.body;
    const result = await col("services").insertOne({
      vendorId: req.user.id,
      vendorName: vendor.name,
      vendorBusinessName: vendor.businessName || "",
      vendorImage: vendor.image || "",
      serviceName: serviceName.trim(),
      category,
      description: description.trim(),
      price: Number(price),
      location: location.trim(),
      images,
      status: "pending",
      isActive: true,
      createdAt: new Date(),
    });

    res.status(201).send({
      success: true,
      message: "Service submitted! Waiting for admin approval.",
      serviceId: result.insertedId,
    });
  } catch (err) {
    serverError(res, "Create Service Error:", err, "Failed to create service!");
  }
});

app.get("/vendor/services", ...vendorOnly, async (req, res) => {
  try {
    const services = await col("services")
      .find({ vendorId: req.user.id })
      .sort({ createdAt: -1 })
      .toArray();
    res.send({ success: true, services });
  } catch (error) {
    serverError(
      res,
      "Vendor Services Error:",
      error,
      "Failed to fetch services!",
    );
  }
});

async function getOwnedService(req, res) {
  const _id = toObjectId(req.params.id);
  if (!_id) {
    fail(res, 400, "Invalid Service ID!");
    return null;
  }
  const service = await col("services").findOne({ _id });
  if (!service) {
    fail(res, 404, "Service not found!");
    return null;
  }
  if (service.vendorId !== req.user.id) {
    fail(res, 403, "You can only manage your own services!");
    return null;
  }
  return service;
}

app.put("/services/:id", ...vendorOnly, async (req, res) => {
  try {
    const service = await getOwnedService(req, res);
    if (!service) return;

    const error = validateServiceBody(req.body);
    if (error) return fail(res, 400, error);

    const { serviceName, category, description, price, location, images } =
      req.body;
    const update = {
      serviceName: serviceName.trim(),
      category,
      description: description.trim(),
      price: Number(price),
      location: location.trim(),
      images,
      updatedAt: new Date(),
    };
    // Approved service edit korle abar review e jabe
    if (service.status === "approved") update.status = "pending";

    await col("services").updateOne({ _id: service._id }, { $set: update });
    res.send({ success: true, message: "Service updated successfully!" });
  } catch (err) {
    serverError(res, "Update Service Error:", err, "Failed to update service!");
  }
});

app.patch("/services/:id/availability", ...vendorOnly, async (req, res) => {
  try {
    const service = await getOwnedService(req, res);
    if (!service) return;

    const { isActive } = req.body;
    if (typeof isActive !== "boolean") {
      return fail(res, 400, "isActive must be true or false!");
    }

    if (isActive && !isPremium(req.user.doc)) {
      const count = await activeServiceCount(req.user.id, service._id);
      if (count >= FREE_SERVICE_LIMIT) {
        return fail(res, 403, "Free plan limit reached! Upgrade to Premium.", {
          code: "LIMIT_REACHED",
        });
      }
    }

    await col("services").updateOne(
      { _id: service._id },
      { $set: { isActive } },
    );
    res.send({
      success: true,
      message: `Service is now ${isActive ? "active" : "inactive"}.`,
    });
  } catch (error) {
    serverError(
      res,
      "Availability Error:",
      error,
      "Failed to update availability!",
    );
  }
});

app.delete("/services/:id", ...vendorOnly, async (req, res) => {
  try {
    const service = await getOwnedService(req, res);
    if (!service) return;
    await col("services").deleteOne({ _id: service._id });
    res.send({ success: true, message: "Service deleted successfully!" });
  } catch (error) {
    serverError(
      res,
      "Delete Service Error:",
      error,
      "Failed to delete service!",
    );
  }
});

// ---------- Vendor: Stats & Bookings ----------
app.get("/vendor/stats", ...vendorOnly, async (req, res) => {
  try {
    const vendorId = req.user.id;
    const [totalServices, activeServices, pendingBookings, acceptedBookings] =
      await Promise.all([
        col("services").countDocuments({ vendorId }),
        col("services").countDocuments({
          vendorId,
          isActive: true,
          status: "approved",
        }),
        col("bookings").countDocuments({ vendorId, status: "pending" }),
        col("bookings").countDocuments({ vendorId, status: "accepted" }),
      ]);
    res.send({
      success: true,
      stats: {
        totalServices,
        activeServices,
        pendingBookings,
        acceptedBookings,
        subscriptionPlan: isPremium(req.user.doc) ? "premium" : "free",
        subscriptionExpiresAt: req.user.doc.subscriptionExpiresAt || null,
      },
    });
  } catch (error) {
    serverError(res, "Vendor Stats Error:", error, "Failed to fetch stats!");
  }
});

app.get("/vendor/bookings", ...vendorOnly, async (req, res) => {
  try {
    const bookings = await col("bookings")
      .find({ vendorId: req.user.id })
      .sort({ createdAt: -1 })
      .toArray();
    res.send({ success: true, bookings });
  } catch (error) {
    serverError(
      res,
      "Vendor Bookings Error:",
      error,
      "Failed to fetch bookings!",
    );
  }
});

app.patch("/bookings/:id/status", ...vendorOnly, async (req, res) => {
  try {
    const _id = toObjectId(req.params.id);
    if (!_id) return fail(res, 400, "Invalid Booking ID!");

    const { status } = req.body;
    if (!["accepted", "rejected"].includes(status)) {
      return fail(res, 400, "Status must be accepted or rejected!");
    }

    const updated = await col("bookings").findOneAndUpdate(
      { _id, vendorId: req.user.id, status: "pending" },
      { $set: { status, updatedAt: new Date() } },
      { returnDocument: "after" },
    );
    if (updated) {
      return res.send({ success: true, message: `Booking ${status}!` });
    }

    const booking = await col("bookings").findOne({ _id });
    if (!booking) return fail(res, 404, "Booking not found!");
    if (booking.vendorId !== req.user.id) {
      return fail(res, 403, "You cannot modify another vendor's booking!");
    }
    return fail(res, 409, "Only pending requests can be accepted or rejected!");
  } catch (error) {
    serverError(
      res,
      "Booking Status Error:",
      error,
      "Failed to update booking!",
    );
  }
});

// ---------- Customer: Bookings ----------
app.post("/bookings", ...customerOnly, async (req, res) => {
  try {
    const { serviceId, eventDate, eventLocation, message } = req.body;
    if (!serviceId || !eventDate || !eventLocation?.trim()) {
      return fail(res, 400, "Please fill in all required fields!");
    }

    const _id = toObjectId(serviceId);
    if (!_id) return fail(res, 400, "Invalid Service ID!");

    const date = new Date(eventDate);
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    if (isNaN(date.getTime()) || date < today) {
      return fail(res, 400, "Please choose a valid future event date!");
    }

    const service = await col("services").findOne({ _id, ...PUBLIC_FILTER });
    if (!service) {
      return fail(res, 404, "Service not found or not available for booking!");
    }
    if (service.vendorId === req.user.id) {
      return fail(res, 403, "You cannot book your own service!");
    }

    const duplicate = await col("bookings").findOne({
      serviceId: service._id,
      customerId: req.user.id,
      eventDate,
      status: { $in: ["pending", "accepted"] },
    });
    if (duplicate) {
      return fail(
        res,
        409,
        "You already have an active booking for this date!",
      );
    }

    const customer = req.user.doc;
    const result = await col("bookings").insertOne({
      serviceId: service._id,
      serviceName: service.serviceName,
      serviceImage: service.images?.[0] || "",
      vendorId: service.vendorId,
      vendorName: service.vendorName || "",
      vendorBusinessName: service.vendorBusinessName || "",
      customerId: req.user.id,
      customerName: customer.name,
      customerEmail: customer.email,
      customerImage: customer.image || "",
      eventDate,
      eventLocation: eventLocation.trim(),
      message: message?.trim() || "",
      status: "pending",
      createdAt: new Date(),
    });

    res.status(201).send({
      success: true,
      message: "Booking submitted successfully!",
      bookingId: result.insertedId,
    });
  } catch (error) {
    serverError(res, "Booking API Error:", error, "Failed to submit booking!");
  }
});

app.get("/customer/bookings", ...customerOnly, async (req, res) => {
  try {
    const bookings = await col("bookings")
      .find({ customerId: req.user.id })
      .sort({ createdAt: -1 })
      .toArray();
    res.send({ success: true, totalBookings: bookings.length, bookings });
  } catch (error) {
    serverError(
      res,
      "Customer Bookings Error:",
      error,
      "Failed to fetch bookings!",
    );
  }
});

app.get("/customer/stats", ...customerOnly, async (req, res) => {
  try {
    const customerId = req.user.id;
    const [total, pending, accepted, rejected] = await Promise.all([
      col("bookings").countDocuments({ customerId }),
      col("bookings").countDocuments({ customerId, status: "pending" }),
      col("bookings").countDocuments({ customerId, status: "accepted" }),
      col("bookings").countDocuments({ customerId, status: "rejected" }),
    ]);
    res.send({ success: true, stats: { total, pending, accepted, rejected } });
  } catch (error) {
    serverError(res, "Customer Stats Error:", error, "Failed to fetch stats!");
  }
});

app.get("/customer/bookings/:id", ...customerOnly, async (req, res) => {
  try {
    const _id = toObjectId(req.params.id);
    if (!_id) return fail(res, 400, "Invalid Booking ID!");
    const booking = await col("bookings").findOne({ _id });
    if (!booking) return fail(res, 404, "Booking not found!");
    if (booking.customerId !== req.user.id) return fail(res, 403, "Forbidden!");
    res.send({ success: true, booking });
  } catch (error) {
    serverError(
      res,
      "Booking Details Error:",
      error,
      "Failed to fetch booking!",
    );
  }
});

app.patch("/bookings/:id/cancel", ...customerOnly, async (req, res) => {
  try {
    const _id = toObjectId(req.params.id);
    if (!_id) return fail(res, 400, "Invalid Booking ID!");

    const updated = await col("bookings").findOneAndUpdate(
      { _id, customerId: req.user.id, status: "pending" },
      { $set: { status: "cancelled", updatedAt: new Date() } },
      { returnDocument: "after" },
    );
    if (updated)
      return res.send({ success: true, message: "Booking cancelled!" });

    const booking = await col("bookings").findOne({ _id });
    if (!booking) return fail(res, 404, "Booking not found!");
    if (booking.customerId !== req.user.id) {
      return fail(res, 403, "You cannot cancel another customer's booking!");
    }
    return fail(res, 409, "Only pending bookings can be cancelled!");
  } catch (error) {
    serverError(
      res,
      "Cancel Booking Error:",
      error,
      "Failed to cancel booking!",
    );
  }
});

// ---------- Payments (Stripe) ----------
app.post(
  "/payments/create-checkout-session",
  ...vendorOnly,
  async (req, res) => {
    try {
      const vendor = req.user.doc;
      if (isPremium(vendor)) {
        return fail(res, 409, "You are already a Premium vendor!");
      }

      const price = Number(process.env.PREMIUM_PRICE_USD || 20);
      const clientUrl = CLIENT_URL.split(",")[0].trim();

      const session = await stripe.checkout.sessions.create({
        mode: "subscription",
        customer_email: vendor.email,
        line_items: [
          {
            quantity: 1,
            price_data: {
              currency: "usd",
              unit_amount: Math.round(price * 100),
              recurring: { interval: "month" },
              product_data: {
                name: "WedPlan Premium Vendor",
                description: "Unlimited services and Premium Vendor badge",
              },
            },
          },
        ],
        metadata: { vendorId: req.user.id },
        subscription_data: { metadata: { vendorId: req.user.id } },
        success_url: `${clientUrl}/payment/success?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${clientUrl}/payment/cancel`,
      });

      await col("transactions").insertOne({
        vendorId: req.user.id,
        vendorName: vendor.name,
        vendorEmail: vendor.email,
        plan: "premium",
        amount: price,
        currency: "usd",
        stripeSessionId: session.id,
        stripeSubscriptionId: null,
        status: "pending",
        createdAt: new Date(),
      });

      res.send({ success: true, url: session.url });
    } catch (error) {
      serverError(
        res,
        "Checkout Session Error:",
        error,
        "Failed to start checkout!",
      );
    }
  },
);

// Read-only: shudhu webhook-verified status dekhay, Premium activate kore na
app.get("/payments/session/:sessionId", ...vendorOnly, async (req, res) => {
  try {
    const transaction = await col("transactions").findOne({
      stripeSessionId: req.params.sessionId,
      vendorId: req.user.id,
    });
    if (!transaction) return fail(res, 404, "Transaction not found!");
    res.send({
      success: true,
      status: transaction.status,
      premiumActive: isPremium(req.user.doc),
      transaction,
    });
  } catch (error) {
    serverError(
      res,
      "Session Status Error:",
      error,
      "Failed to verify payment!",
    );
  }
});

app.post("/payments/cancel-subscription", ...vendorOnly, async (req, res) => {
  try {
    const subscriptionId = req.user.doc.stripeSubscriptionId;
    if (!subscriptionId) return fail(res, 400, "No active subscription found!");

    await stripe.subscriptions.update(subscriptionId, {
      cancel_at_period_end: true,
    });
    res.send({
      success: true,
      message:
        "Subscription will be cancelled at the end of the billing period.",
    });
  } catch (error) {
    serverError(
      res,
      "Cancel Subscription Error:",
      error,
      "Failed to cancel subscription!",
    );
  }
});

// ---------- Admin ----------
app.get("/admin/stats", ...adminOnly, async (req, res) => {
  try {
    const users = col("user");
    const [
      totalUsers,
      totalVendors,
      totalCustomers,
      totalServices,
      pendingServices,
      totalTransactions,
    ] = await Promise.all([
      users.countDocuments({ role: { $ne: "admin" } }),
      users.countDocuments({ role: "vendor" }),
      users.countDocuments({ role: "customer" }),
      col("services").countDocuments(),
      col("services").countDocuments({ status: "pending" }),
      col("transactions").countDocuments(),
    ]);
    res.send({
      success: true,
      stats: {
        totalUsers,
        totalVendors,
        totalCustomers,
        totalServices,
        pendingServices,
        totalTransactions,
      },
    });
  } catch (error) {
    serverError(res, "Admin Stats Error:", error, "Failed to fetch stats!");
  }
});

app.get("/admin/users", ...adminOnly, async (req, res) => {
  try {
    const { search, role } = req.query;
    const filter = {};
    if (role && ["customer", "vendor", "admin"].includes(role))
      filter.role = role;
    if (search) {
      const regex = { $regex: escapeRegex(search), $options: "i" };
      filter.$or = [{ name: regex }, { email: regex }];
    }
    const users = await col("user")
      .find(filter, { projection: { password: 0 } })
      .sort({ createdAt: -1 })
      .toArray();
    res.send({ success: true, users });
  } catch (error) {
    serverError(res, "Admin Users Error:", error, "Failed to fetch users!");
  }
});

app.get("/admin/users/:id", ...adminOnly, async (req, res) => {
  try {
    const user = await findUser(req.params.id);
    if (!user) return fail(res, 404, "User not found!");
    const [services, bookings] = await Promise.all([
      col("services").countDocuments({ vendorId: String(user._id) }),
      col("bookings").countDocuments({
        $or: [{ customerId: String(user._id) }, { vendorId: String(user._id) }],
      }),
    ]);
    res.send({ success: true, user, services, bookings });
  } catch (error) {
    serverError(
      res,
      "Admin User Details Error:",
      error,
      "Failed to fetch user!",
    );
  }
});

app.patch("/admin/users/:id/block", ...adminOnly, async (req, res) => {
  try {
    const { isBlocked } = req.body;
    if (typeof isBlocked !== "boolean") {
      return fail(res, 400, "isBlocked must be true or false!");
    }
    const user = await findUser(req.params.id);
    if (!user) return fail(res, 404, "User not found!");
    if (user.role === "admin")
      return fail(res, 403, "Admin accounts cannot be blocked!");

    await col("user").updateOne({ _id: user._id }, { $set: { isBlocked } });
    res.send({
      success: true,
      message: isBlocked ? "User blocked!" : "User unblocked!",
    });
  } catch (error) {
    serverError(res, "Block User Error:", error, "Failed to update user!");
  }
});

app.get("/admin/services", ...adminOnly, async (req, res) => {
  try {
    const { search, status, category } = req.query;
    const filter = {};
    if (status && ["pending", "approved", "rejected"].includes(status))
      filter.status = status;
    if (category) filter.category = category;
    if (search)
      filter.serviceName = { $regex: escapeRegex(search), $options: "i" };

    const services = await col("services")
      .find(filter)
      .sort({ createdAt: -1 })
      .toArray();
    res.send({ success: true, services });
  } catch (error) {
    serverError(
      res,
      "Admin Services Error:",
      error,
      "Failed to fetch services!",
    );
  }
});

app.patch("/admin/services/:id/status", ...adminOnly, async (req, res) => {
  try {
    const _id = toObjectId(req.params.id);
    if (!_id) return fail(res, 400, "Invalid Service ID!");
    const { status } = req.body;
    if (!["pending", "approved", "rejected"].includes(status)) {
      return fail(res, 400, "Invalid status!");
    }
    const result = await col("services").updateOne(
      { _id },
      { $set: { status } },
    );
    if (!result.matchedCount) return fail(res, 404, "Service not found!");
    res.send({ success: true, message: `Service ${status}!` });
  } catch (error) {
    serverError(
      res,
      "Admin Service Status Error:",
      error,
      "Failed to update service!",
    );
  }
});

app.delete("/admin/services/:id", ...adminOnly, async (req, res) => {
  try {
    const _id = toObjectId(req.params.id);
    if (!_id) return fail(res, 400, "Invalid Service ID!");
    const result = await col("services").deleteOne({ _id });
    if (!result.deletedCount) return fail(res, 404, "Service not found!");
    res.send({ success: true, message: "Service deleted!" });
  } catch (error) {
    serverError(
      res,
      "Admin Delete Service Error:",
      error,
      "Failed to delete service!",
    );
  }
});

// Read-only: payment record edit korar kono route nai
app.get("/admin/transactions", ...adminOnly, async (req, res) => {
  try {
    const transactions = await col("transactions")
      .find()
      .sort({ createdAt: -1 })
      .toArray();
    res.send({ success: true, transactions });
  } catch (error) {
    serverError(
      res,
      "Admin Transactions Error:",
      error,
      "Failed to fetch transactions!",
    );
  }
});

// ---------- 404 & Error handlers ----------
app.use((req, res) => fail(res, 404, "Route not found!"));

app.use((err, req, res, next) => {
  console.error("Unhandled Error:", err);
  fail(res, 500, "Something went wrong!");
});

// ---------- Start ----------
if (!process.env.VERCEL) {
  app.listen(port, () => console.log(`WedPlan Server running on port ${port}`));
}

export default app;
