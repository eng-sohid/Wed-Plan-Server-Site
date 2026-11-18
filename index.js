import express from "express";
import cors from "cors";
import "dotenv/config";
import { MongoClient, ObjectId } from "mongodb";

// Express App
const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

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
app.post("/bookings", async (req, res) => {
  try {
    const { serviceId, name, email, phone, weddingDate, message } = req.body;

    // Check Required Fields
    if (!serviceId || !name || !email || !phone || !weddingDate) {
      return res.status(400).send({
        success: false,
        message: "Please fill in all required fields!",
      });
    }

    // Check Service ID
    if (!ObjectId.isValid(serviceId)) {
      return res.status(400).send({
        success: false,
        message: "Invalid Service ID!",
      });
    }

    // Find Selected Service
    const servicesCollection = db.collection("services");

    const service = await servicesCollection.findOne({
      _id: new ObjectId(serviceId),
    });

    if (!service) {
      return res.status(404).send({
        success: false,
        message: "Service not found!",
      });
    }

    // Booking Collection
    const bookingsCollection = db.collection("bookings");

    // Save Booking Data
    const booking = {
      serviceId: service._id,
      serviceTitle: service.title,
      name,
      email,
      phone,
      weddingDate,
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
