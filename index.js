import express from "express";
import cors from "cors";
import "dotenv/config";
import { MongoClient, ObjectId } from "mongodb";
import { jwtVerify } from "jose";

// Express App
const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// JWT Verification Middleware
async function verifyToken(req, res, next) {
  try {
    const authorization = req.headers.authorization;

    // Check Authorization Header
    if (!authorization || !authorization.startsWith("Bearer ")) {
      return res.status(401).send({
        success: false,
        message: "Unauthorized! Token is required.",
      });
    }

    const token = authorization.split(" ")[1];

    const secret = process.env.JWT_SECRET;

    if (!secret) {
      throw new Error("JWT_SECRET is missing!");
    }

    // Verify JWT
    const { payload } = await jwtVerify(
      token,
      new TextEncoder().encode(secret),
      {
        issuer: "wedplan-client",
        audience: "wedplan-api",
        algorithms: ["HS256"],
      },
    );

    // Check user information
    if (
      !payload.sub ||
      !["customer", "vendor", "admin"].includes(payload.role)
    ) {
      return res.status(401).send({
        success: false,
        message: "Invalid user information!",
      });
    }

    // Attach authenticated user
    req.user = {
      id: payload.sub,
      email: payload.email,
      role: payload.role,
    };

    next();
  } catch (error) {
    return res.status(401).send({
      success: false,
      message: "Invalid or expired token!",
    });
  }
}

// Role Verification Middleware
function verifyRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return res.status(403).send({
        success: false,
        message: "Forbidden! You don't have permission.",
      });
    }

    next();
  };
}

// Get Logged-in Customer's Bookings
app.get(
  "/customer/bookings",
  verifyToken,
  verifyRole("customer"),
  async (req, res) => {
    try {
      const bookingsCollection = db.collection("bookings");

      // Fetch only logged-in customer's bookings
      const bookings = await bookingsCollection
        .find({
          customerId: req.user.id,
        })
        .sort({ createdAt: -1 })
        .toArray();

      res.status(200).send({
        success: true,
        totalBookings: bookings.length,
        bookings,
      });
    } catch (error) {
      console.error("Customer Bookings Error:", error);

      res.status(500).send({
        success: false,
        message: "Failed to fetch bookings!",
      });
    }
  },
);

// MongoDB Connection
const client = new MongoClient(process.env.MONGODB_URI);

let db;

// Services Data
const services = [
  {
    title: "Wedding Photography",
    category: "Photography",
    description:
      "Capture every beautiful moment of your wedding with professional photography.",
    image:
      "https://images.unsplash.com/photo-1519741497674-611481863552?w=1000",
  },
  {
    title: "Wedding Venues",
    category: "Venue",
    description:
      "Find the perfect venue to celebrate your special day with family and friends.",
    image:
      "https://images.unsplash.com/photo-1519167758481-83f550bb49b3?w=1000",
  },
  {
    title: "Bridal Makeup",
    category: "Beauty",
    description:
      "Feel confident and beautiful with professional bridal makeup services.",
    image:
      "https://images.unsplash.com/photo-1487412720507-e7ab37603c6f?w=1000",
  },
  {
    title: "Catering Services",
    category: "Catering",
    description:
      "Make your celebration memorable with delicious food and excellent catering.",
    image:
      "https://images.unsplash.com/photo-1511795409834-ef04bbd61622?w=1000",
  },
  {
    title: "Wedding Decoration",
    category: "Decoration",
    description:
      "Transform your wedding venue with elegant and beautiful decorations.",
    image:
      "https://images.unsplash.com/photo-1507504031003-b417219a0fde?w=1000",
  },
  {
    title: "Wedding Planning",
    category: "Planning",
    description:
      "Let our expert planners organize every detail of your dream wedding.",
    image:
      "https://images.unsplash.com/photo-1464366400600-7168b8af9bc3?w=1000",
  },
];

// Connect MongoDB
async function connectToMongoDB() {
  try {
    await client.connect();

    db = client.db("wedplan");

    console.log("MongoDB Connected Successfully!");

    // Create Services Collection Data if Empty
    const servicesCollection = db.collection("services");

    const totalServices = await servicesCollection.countDocuments();

    if (totalServices === 0) {
      await servicesCollection.insertMany(services);
      console.log("6 Services Added Successfully!");
    } else {
      console.log("Services Data Already Exists!");
    }
  } catch (error) {
    console.error("MongoDB Connection Failed:", error);
    process.exit(1);
  }
}

// Default Route
app.get("/", (req, res) => {
  res.send("WedPlan Server is Running!");
});

// Database Test API
app.get("/test-db", async (req, res) => {
  try {
    await db.command({ ping: 1 });

    res.send({
      success: true,
      message: "Database Connected Successfully!",
    });
  } catch (error) {
    res.status(500).send({
      success: false,
      message: "Database Connection Failed!",
    });
  }
});

// Get All Services API
app.get("/services", async (req, res) => {
  try {
    const servicesCollection = db.collection("services");

    const allServices = await servicesCollection.find().toArray();

    res.status(200).send({
      success: true,
      services: allServices,
    });
  } catch (error) {
    console.error("Services API Error:", error);

    res.status(500).send({
      success: false,
      message: "Failed to fetch services!",
    });
  }
});
// Get Single Service Details API
// Get Single Service Details API
app.get("/services/:id", async (req, res) => {
  try {
    const { id } = req.params;

    // Check Valid MongoDB ID
    if (!ObjectId.isValid(id)) {
      return res.status(400).send({
        success: false,
        message: "Invalid Service ID!",
      });
    }

    const servicesCollection = db.collection("services");

    const service = await servicesCollection.findOne({
      _id: new ObjectId(id),
    });

    if (!service) {
      return res.status(404).send({
        success: false,
        message: "Service not found!",
      });
    }

    res.status(200).send({
      success: true,
      service,
    });
  } catch (error) {
    console.error("Single Service API Error:", error);

    res.status(500).send({
      success: false,
      message: "Failed to fetch service details!",
    });
  }
});

// Vendor Create Service API
app.post("/services", verifyToken, verifyRole("vendor"), async (req, res) => {
  try {
    const { serviceName, category, description, price, location, images } =
      req.body;

    // Validate required fields
    if (
      !serviceName ||
      !category ||
      !description ||
      price === undefined ||
      !location
    ) {
      return res.status(400).send({
        success: false,
        message: "Please fill in all required fields!",
      });
    }

    const servicesCollection = db.collection("services");

    // Create new service
    const newService = {
      vendorId: req.user.id,
      vendorName: req.user.email,
      serviceName,
      category,
      description,
      price: Number(price),
      location,
      images: Array.isArray(images) ? images : [],
      status: "pending",
      createdAt: new Date(),
    };

    const result = await servicesCollection.insertOne(newService);

    res.status(201).send({
      success: true,
      message: "Service created successfully!",
      serviceId: result.insertedId,
    });
  } catch (error) {
    console.error("Create Service Error:", error);

    res.status(500).send({
      success: false,
      message: "Failed to create service!",
    });
  }
});

// Contact Form API
app.post("/contact", async (req, res) => {
  try {
    const { name, email, subject, message } = req.body;

    // Check Required Fields
    if (!name || !email || !subject || !message) {
      return res.status(400).send({
        success: false,
        message: "All fields are required!",
      });
    }

    // Save Contact Message
    const contactCollection = db.collection("contacts");

    const result = await contactCollection.insertOne({
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
    console.error("Contact API Error:", error);

    res.status(500).send({
      success: false,
      message: "Failed to send message!",
    });
  }
});

// Wedding Service Booking API

app.post("/bookings", verifyToken, verifyRole("customer"), async (req, res) => {
  try {
    const { serviceId, eventDate, eventLocation, message } = req.body;

    // Validate required fields
    if (!serviceId || !eventDate || !eventLocation) {
      return res.status(400).send({
        success: false,
        message: "Please fill in all required fields!",
      });
    }

    if (!ObjectId.isValid(serviceId)) {
      return res.status(400).send({
        success: false,
        message: "Invalid Service ID!",
      });
    }

    const servicesCollection = db.collection("services");
    const bookingsCollection = db.collection("bookings");

    // Find selected service
    const service = await servicesCollection.findOne({
      _id: new ObjectId(serviceId),
    });

    if (!service) {
      return res.status(404).send({
        success: false,
        message: "Service not found!",
      });
    }

    // Get vendor ID from service
    const vendorId = service.vendorId?.toString();

    if (!vendorId) {
      return res.status(400).send({
        success: false,
        message: "Vendor information is missing!",
      });
    }

    // Prevent vendor from booking own service
    if (vendorId === req.user.id) {
      return res.status(403).send({
        success: false,
        message: "You cannot book your own service!",
      });
    }

    // Check duplicate active booking
    const existingBooking = await bookingsCollection.findOne({
      serviceId: service._id,
      customerId: req.user.id,
      eventDate,
      status: { $in: ["pending", "accepted"] },
    });

    if (existingBooking) {
      return res.status(409).send({
        success: false,
        message: "You already have an active booking for this date!",
      });
    }

    // Save booking
    const booking = {
      serviceId: service._id,
      serviceName: service.serviceName || service.title,
      serviceImage: service.images?.[0] || service.image || "",
      vendorId,
      vendorName: service.vendorName || "",
      customerId: req.user.id,
      eventDate,
      eventLocation,
      message: message || "",
      status: "pending",
      createdAt: new Date(),
    };

    const result = await bookingsCollection.insertOne(booking);

    res.status(201).send({
      success: true,
      message: "Booking submitted successfully!",
      bookingId: result.insertedId,
    });
  } catch (error) {
    console.error("Booking API Error:", error);

    res.status(500).send({
      success: false,
      message: "Failed to submit booking!",
    });
  }
});

// Start Server
async function startServer() {
  await connectToMongoDB();

  app.listen(port, () => {
    console.log(`WedPlan Server running on port ${port}`);
  });
}

startServer();
