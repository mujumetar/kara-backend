
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
// const cors = require("cors");
const multer = require("multer");
const Razorpay = require("razorpay");
const crypto = require("crypto");
const { CloudinaryStorage } = require("multer-storage-cloudinary");
const cloudinary = require("cloudinary").v2;
const twilio = require("twilio");
const nodemailer = require("nodemailer");

const app = express();
app.use(express.json());


const cors = require("cors");

app.use(cors({
  origin: [
    "http://localhost:5173",
    "https://kara-ent.vercel.app"
  ],
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

// ✅ SAFE for Express 4 + Vercel
app.options(/.*/, cors());


/* ================= CONFIG ================= */
const JWT_SECRET = process.env.JWT_SECRET;

// Twilio configuration - In production, use environment variables
const client = twilio(
  process.env.TWILIO_SID || 'AC8cef5806b7ff1158a3f8b1cab10d580f',
  process.env.TWILIO_AUTH_TOKEN || '91f6a0ce2de2d16e683620c6049f76bb'
);

const TWILIO_PHONE = process.env.TWILIO_PHONE || '+12055457341';

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected"))
  .catch(console.error);

/* ================= CLOUDINARY ================= */
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_NAME,
  api_key: process.env.CLOUDINARY_KEY,
  api_secret: process.env.CLOUDINARY_SECRET,
});

const storage = new CloudinaryStorage({
  cloudinary,
  params: { folder: "flipkart", allowed_formats: ["jpg", "png", "jpeg"] },
});

const upload = multer({ storage });

/* ================= RAZORPAY ================= */
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY,       // rzp_test_XXXX
  key_secret: process.env.RAZORPAY_SECRET // 9oRhO0XXXX
});

/* ================= MODELS ================= */
const User = mongoose.model(
  "User",
  new mongoose.Schema(
    {
      name: String,
      email: { type: String, unique: true },
      password: String,
      phone: String,
      role: { type: String, default: "user" },

      isBanned: {
        type: Boolean,
        default: false,
      },

      profileImage: String,
      supercoins: { type: Number, default: 0 },
      addresses: { type: Array, default: [] },

      cart: [
        {
          productId: String,
          title: String,
          price: Number,
          quantity: { type: Number, default: 1 },
          image: String,
        },
      ],
    },
    { timestamps: true }
  )
);


const Category = mongoose.model(
  "Category",
  new mongoose.Schema({
    name: String,
    subcategories: [String],
  })
);

const ProductSchema = new mongoose.Schema(
  {
    title: { type: String, required: true },
    price: { type: Number, required: true },
    images: [String],
    category: String,
    subcategory: String,
    description: String,
    stock: Number,

    // ⭐ REVIEWS
    reviews: [
      {
        userId: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "User",
          required: true
        },
        name: String, // optional, fallback to user.name
        rating: {
          type: Number,
          min: 1,
          max: 5,
          required: true
        },
        comment: String,
        createdAt: { type: Date, default: Date.now }
      }
    ],

    avgRating: { type: Number, default: 0 }
  },
  { timestamps: true }
);

const Product = mongoose.model("Product", ProductSchema);

const renderTemplate = (html, data = {}) => {
  return html.replace(/\{\{(.*?)\}\}/g, (_, key) => {
    return data[key.trim()] ?? "";
  });
};


const Order = mongoose.model(
  "Order",
  new mongoose.Schema(
    {
      userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User"
      },
      products: [
        {
          _id: String,
          title: String,
          price: Number,
          quantity: Number,
        },
      ],
      address: Object,
      paymentId: String,
      totalAmount: { type: Number, required: true },

      status: {
        type: String,
        enum: ["Pending", "Processing", "Confirmed", "Shipped", "Delivered"],
        default: "Pending",
      },
    },
    { timestamps: true }
  )
);


const Slider = mongoose.model(
  "Slider",
  new mongoose.Schema({
    title: String,
    image: String,
    link: String,
  })
);
// Backend – EmailTemplate schema
// Replace your current EmailTemplate model with this:
const EmailTemplate = mongoose.model(
  "EmailTemplate",
  new mongoose.Schema(
    {
      name: { type: String, required: true },           // Human readable name
      key: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true
      },
      subject: { type: String, required: true },
      html: { type: String, required: true },
      variables: [String],                             // e.g. ["name", "orderId", "amount"]
      isActive: { type: Boolean, default: true },

      // ── NEW FIELD ──
      type: {
        type: String,
        enum: ["transactional", "marketing"],
        default: "transactional",
        required: true
      },
    },
    { timestamps: true }
  )
);


/* ================= MIDDLEWARE ================= */
const auth = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: "No token" });

  const token = authHeader.startsWith("Bearer ")
    ? authHeader.split(" ")[1]
    : authHeader;

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id);

    if (!user) return res.status(401).json({ message: "User not found" });
    if (user.isBanned)
      return res.status(403).json({ message: "User is banned" });

    req.user = { id: user._id };
    next();
  } catch (err) {
    res.status(401).json({ message: "Invalid token" });
  }
};



const adminAuth = async (req, res, next) => {
  const user = await User.findById(req.user.id);
  if (user.role !== "admin") return res.status(403).json({ message: "Admin only" });
  next();
};

/* ================= AUTH ================= */
app.post("/api/register", async (req, res) => {
  try {
    const hashed = await bcrypt.hash(req.body.password, 10);
    const user = await User.create({ ...req.body, password: hashed });

    // ✅ SEND WELCOME EMAIL
    try {
      const template = await EmailTemplate.findOne({
        key: "welcomeuser",
        isActive: true
      });

      if (template) {
        const html = renderTemplate(template.html, {
          name: user.name || "Customer",
          websiteUrl: "https://karaenterprises.com",
          year: new Date().getFullYear()
        });

        await sendEmail({
          to: user.email,
          subject: template.subject,
          html
        });
      }
    } catch (emailError) {
      console.error("WELCOME EMAIL ERROR:", emailError);
      // ❗ Do not block registration if email fails
    }

    res.json(user);
  } catch (error) {
    if (error.code === 11000) {
      res.status(400).json({ message: "Email already exists" });
    } else {
      console.error(error);
      res.status(500).json({ message: "Failed to register user" });
    }
  }
});


app.post("/api/login", async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    if (!user) return res.status(400).json({ message: "User not found" });

    if (user.isBanned)
      return res.status(403).json({ message: "Your account is banned" });

    const match = await bcrypt.compare(req.body.password, user.password);
    if (!match) return res.status(400).json({ message: "Wrong password" });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });

    res.json({ token, user });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to login" });
  }
});


app.get("/api/admin/users", auth, adminAuth, async (req, res) => {
  try {
    const { search } = req.query;
    let filter = {};
    if (search) {
      filter = { $or: [{ name: { $regex: search, $options: 'i' } }, { email: { $regex: search, $options: 'i' } }] };
    }
    const users = await User.find(filter).sort({ createdAt: -1 });
    res.json(users);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to fetch users" });
  }
});


app.patch("/api/admin/users/:id/ban", auth, adminAuth, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message: "User not found" });

    user.isBanned = !user.isBanned;
    await user.save();

    // Send email notification for ban/unban using template
    const status = user.isBanned ? 'banned' : 'unbanned';
    const key = `account${status.charAt(0).toUpperCase() + status.slice(1)}`;
    const template = await EmailTemplate.findOne({ key, isActive: true });
    if (template) {
      const html = renderTemplate(template.html, { name: user.name });
      await sendEmail({
        to: user.email,
        subject: template.subject,
        html
      });
    }

    res.json({
      success: true,
      isBanned: user.isBanned,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to update user ban status" });
  }
});


/* ================= SMS NOTIFICATIONS ================= */
async function sendAdminSMS(message) {
  try {
    const admins = await User.find({ role: "admin" });
    if (admins.length === 0) {
      console.log("No admins found for SMS");
      return;
    }

    for (const admin of admins) {
      if (admin.phone) {
        try {
          await client.messages.create({
            body: message,
            from: process.env.TWILIO_PHONE,
            to: admin.phone
          });
          console.log(`SMS sent to ${admin.phone}`);
        } catch (smsError) {
          console.error(`SMS failed for ${admin.phone}:`, smsError);
        }
      }
    }
  } catch (error) {
    console.error("Error in sendAdminSMS:", error);
  }
}

app.post("/api/admin/email-templates", auth, adminAuth, async (req, res) => {
  try {
    const template = await EmailTemplate.create(req.body);
    res.json(template);
  } catch (error) {
    console.error("EMAIL TEMPLATE ERROR:", error);

    // 👇 send actual reason to frontend
    res.status(400).json({
      message: error.message,
      errors: error.errors
    });
  }
});

// Bulk send marketing email to all non-banned users
app.post("/api/admin/email/marketing-bulk", auth, adminAuth, async (req, res) => {
  try {
    const { templateKey } = req.body;

    const template = await EmailTemplate.findOne({
      key: templateKey,
      type: "marketing",          // Important: only allow marketing type
      isActive: true,
    });

    if (!template) {
      return res.status(404).json({ message: "Marketing template not found or not allowed" });
    }

    const users = await User.find({ isBanned: false, email: { $exists: true } });

    let sentCount = 0;

    for (const user of users) {
      try {
        const html = renderTemplate(template.html, {
          name: user.name || "Customer",
          // You can pass more data from frontend if needed
        });

        await sendEmail({
          to: user.email,
          subject: template.subject,
          html,
        });

        sentCount++;
      } catch (emailErr) {
        console.error(`Failed to send to ${user.email}:`, emailErr);
      }
    }

    res.json({
      success: true,
      sent: sentCount,
      totalUsers: users.length,
      message: `Sent to ${sentCount} users`,
    });
  } catch (error) {
    console.error("Bulk marketing email error:", error);
    res.status(500).json({ message: "Failed to send bulk marketing email" });
  }
});
app.get("/api/admin/email-templates", auth, adminAuth, async (req, res) => {
  try {
    res.json(await EmailTemplate.find().sort({ createdAt: -1 }));
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to fetch email templates" });
  }
});
app.put("/api/admin/email-templates/:id", auth, adminAuth, async (req, res) => {
  try {
    const template = await EmailTemplate.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true }
    );
    if (!template) return res.status(404).json({ message: "Template not found" });
    res.json(template);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to update email template" });
  }
});
app.delete("/api/admin/email-templates/:id", auth, adminAuth, async (req, res) => {
  try {
    await EmailTemplate.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to delete email template" });
  }
});


const mailer = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.MAIL_USER || "karaentonline@gmail.com",
    pass: process.env.MAIL_PASS || "qayz eeiy xika wayy"
  }
});

const sendEmail = async ({ to, subject, html }) => {
  await mailer.sendMail({
    from: `"Flipkart Clone" <no-reply@karaenterprises.com>`,
    to,
    subject,
    html
  });
};
app.post("/api/admin/email/promo", auth, adminAuth, async (req, res) => {
  try {
    const { templateKey, data } = req.body;

    const template = await EmailTemplate.findOne({
      key: templateKey,
      isActive: true
    });

    if (!template)
      return res.status(404).json({ message: "Template not found" });

    const users = await User.find({ isBanned: false });

    for (const user of users) {
      const html = renderTemplate(template.html, {
        name: user.name,
        ...data
      });

      await sendEmail({
        to: user.email,
        subject: template.subject,
        html
      });
    }

    res.json({ success: true, sent: users.length });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to send promo emails" });
  }
});

app.post("/api/admin/email/payment-reminder", auth, adminAuth, async (req, res) => {
  try {
    const template = await EmailTemplate.findOne({
      key: "paymentReminder",
      isActive: true
    });

    if (!template) return res.status(404).json({ message: "Template not found" });

    const orders = await Order.find({ status: "Pending" }).populate("userId");

    for (const order of orders) {
      if (!order.userId?.email) continue;

      const html = renderTemplate(template.html, {
        name: order.userId.name,
        amount: order.totalAmount
      });

      await sendEmail({
        to: order.userId.email,
        subject: template.subject,
        html
      });
    }

    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to send payment reminders" });
  }
});





/* ================= PROFILE ================= */
app.get("/api/profile", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    const orders = await Order.find({ userId: req.user.id });
    res.json({ ...user.toObject(), orders });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to fetch profile" });
  }
});

app.put("/api/profile", auth, upload.single("profileImage"), async (req, res) => {
  try {
    const update = { ...req.body };
    if (req.file) update.profileImage = req.file.path;
    const user = await User.findByIdAndUpdate(req.user.id, update, { new: true });
    res.json(user);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to update profile" });
  }
});

/* ================= CATEGORIES ================= */
app.post("/api/categories", auth, adminAuth, async (req, res) => {
  try {
    const category = await Category.create(req.body);
    res.json(category);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to create category" });
  }
});
app.get("/api/categories", async (req, res) => {
  try {
    res.json(await Category.find());
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to fetch categories" });
  }
});

// New endpoint: Get subcategories for a specific category (helps with frontend dropdowns for better filtration UX)
app.get("/api/categories/:name/subcategories", async (req, res) => {
  try {
    const category = await Category.findOne({ name: req.params.name });
    if (!category) return res.status(404).json({ message: "Category not found" });
    res.json(category.subcategories);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to fetch subcategories" });
  }
});

app.put("/api/categories/:id", auth, adminAuth, async (req, res) => {
  try {
    const category = await Category.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!category) return res.status(404).json({ message: "Category not found" });
    res.json(category);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to update category" });
  }
});

app.delete("/api/categories/:id", auth, adminAuth, async (req, res) => {
  try {
    await Category.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to delete category" });
  }
});

/* ================= PRODUCTS ================= */
app.post("/api/products", auth, adminAuth, upload.array("images", 5), async (req, res) => {
  try {
    // Validation for category and subcategory to ensure data integrity for better filtration
    if (req.body.category) {
      const categoryDoc = await Category.findOne({ name: req.body.category });
      if (!categoryDoc) {
        return res.status(400).json({ message: "Category not found" });
      }
      if (req.body.subcategory && !categoryDoc.subcategories.includes(req.body.subcategory)) {
        return res.status(400).json({ message: "Subcategory is not valid for the selected category" });
      }
    }

    const images = req.files.map((f) => f.path);
    const product = await Product.create({ ...req.body, images });
    res.json(product);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to create product" });
  }
});
app.get("/api/products", async (req, res) => {
  try {
    const { category, subcategory, minPrice, maxPrice, search } = req.query;
    let filter = {};
    if (search) filter.title = { $regex: search, $options: 'i' };
    if (category) filter.category = category;
    if (subcategory) filter.subcategory = subcategory;
    if (minPrice || maxPrice)
      filter.price = { ...(minPrice && { $gte: Number(minPrice) }), ...(maxPrice && { $lte: Number(maxPrice) }) };
    res.json(await Product.find(filter));
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to fetch products" });
  }
});

app.put("/api/products/:id", auth, adminAuth, upload.array("images", 5), async (req, res) => {
  try {
    const update = { ...req.body };
    if (req.files && req.files.length > 0) {
      update.images = req.files.map((f) => f.path);
    }
    const product = await Product.findByIdAndUpdate(req.params.id, update, { new: true });
    if (!product) return res.status(404).json({ message: "Product not found" });
    res.json(product);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to update product" });
  }
});

// ✅ GET SINGLE PRODUCT BY ID
app.get("/api/products/:id", async (req, res) => {
  try {
    const product = await Product.findById(req.params.id)
      .populate("reviews.userId", "name");

    if (!product) return res.status(404).json({ message: "Product not found" });

    // Map reviews so frontend always has `name` string
    const reviews = product.reviews.map(r => ({
      _id: r._id,
      userId: r.userId,
      name: r.name || r.userId?.name || "Anonymous",
      rating: r.rating,
      comment: r.comment,
      createdAt: r.createdAt
    }));

    res.json({ ...product.toObject(), reviews });
  } catch (error) {
    console.error(error);
    if (error.name === 'CastError') {
      res.status(400).json({ message: "Invalid product ID" });
    } else {
      res.status(500).json({ message: "Failed to fetch product" });
    }
  }
});



/* ================= PRODUCT REVIEWS ================= */

// ⭐ Add review (only if user ordered product)
app.post("/api/products/:id/review", auth, async (req, res) => {
  try {
    const { rating, comment } = req.body;
    if (!rating || rating < 1 || rating > 5)
      return res.status(400).json({ message: "Rating must be 1 to 5" });

    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ message: "Product not found" });

    // Ensure user purchased this product
    const order = await Order.findOne({
      userId: req.user.id,
      "products._id": req.params.id
    });
    if (!order) return res.status(403).json({ message: "Only purchased products can be reviewed" });

    // Prevent duplicate review
    const alreadyReviewed = product.reviews.find(
      r => r.userId.toString() === req.user.id.toString()
    );
    if (alreadyReviewed) return res.status(400).json({ message: "Already reviewed" });

    const user = await User.findById(req.user.id);

    // Add review
    product.reviews.push({
      userId: req.user.id,
      name: user.name,
      rating,
      comment
    });

    // Recalculate avgRating
    product.avgRating =
      product.reviews.reduce((sum, r) => sum + r.rating, 0) / product.reviews.length;

    await product.save();

    // Populate reviews for safe frontend rendering
    const populatedProduct = await Product.findById(req.params.id)
      .populate("reviews.userId", "name");

    const reviews = populatedProduct.reviews.map(r => ({
      _id: r._id,
      userId: r.userId,
      name: r.name || r.userId?.name || "Anonymous",
      rating: r.rating,
      comment: r.comment,
      createdAt: r.createdAt
    }));

    res.json({ success: true, avgRating: populatedProduct.avgRating, reviews });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to add review" });
  }
});




app.delete("/api/products/:id", auth, adminAuth, async (req, res) => {
  try {
    await Product.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to delete product" });
  }
});

/* ================= CART ================= */

app.get("/api/cart", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    res.json(user.cart || []);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to fetch cart" });
  }
});


app.post("/api/cart/add", auth, async (req, res) => {
  try {
    const { product } = req.body;
    const user = await User.findById(req.user.id);
    const existing = user.cart.find((p) => p.productId === product._id);
    if (existing) existing.quantity += 1;
    else
      user.cart.push({
        productId: product._id,
        title: product.title,
        price: product.price,
        image: product.images?.[0],
        quantity: 1,
      });
    await user.save();
    res.json(user.cart);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to add to cart" });
  }
});

// Update cart quantity
app.put("/api/cart/update", auth, async (req, res) => {
  try {
    const { productId, quantity } = req.body;
    const user = await User.findById(req.user.id);
    const item = user.cart.find((p) => p.productId === productId);
    if (!item) return res.status(404).json({ message: "Item not found" });
    item.quantity = quantity;
    await user.save();
    res.json(user.cart);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to update cart" });
  }
});

// Remove a single cart item
app.delete("/api/cart/remove", auth, async (req, res) => {
  try {
    const { productId } = req.body;
    const user = await User.findById(req.user.id);
    user.cart = user.cart.filter((p) => p.productId !== productId);
    await user.save();
    res.json(user.cart);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to remove from cart" });
  }
});

app.post("/api/cart/clear", auth, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.user.id, { cart: [] });
    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to clear cart" });
  }
});

/* ================= ADDRESSES ================= */
// Add a new address
app.post("/api/addresses", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    user.addresses.push(req.body);
    await user.save();
    res.json(user.addresses);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to add address" });
  }
});

// Delete an address
app.delete("/api/addresses/:idx", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    const idx = Number(req.params.idx);
    if (idx >= 0 && idx < user.addresses.length) {
      user.addresses.splice(idx, 1);
      await user.save();
    }
    res.json(user.addresses);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to delete address" });
  }
});

/* ================= SLIDER ================= */
app.post("/api/slider", auth, adminAuth, upload.single("image"), async (req, res) => {
  try {
    const slide = await Slider.create({ title: req.body.title, link: req.body.link, image: req.file.path });
    res.json(slide);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to create slider" });
  }
});
app.get("/api/slider", async (req, res) => {
  try {
    res.json(await Slider.find());
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to fetch sliders" });
  }
});

app.put("/api/slider/:id", auth, adminAuth, upload.single("image"), async (req, res) => {
  try {
    const update = { title: req.body.title, link: req.body.link };
    if (req.file) update.image = req.file.path;
    const slide = await Slider.findByIdAndUpdate(req.params.id, update, { new: true });
    if (!slide) return res.status(404).json({ message: "Slide not found" });
    res.json(slide);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to update slider" });
  }
});

app.delete("/api/slider/:id", auth, adminAuth, async (req, res) => {
  try {
    await Slider.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to delete slider" });
  }
});

/* ================= RAZORPAY ================= */
app.post("/api/payment/create-order", auth, async (req, res) => {
  try {
    const { amount } = req.body;
    if (!amount || amount <= 0) return res.status(400).json({ message: "Invalid amount" });

    const options = {
      amount: amount * 100, // Razorpay expects paise
      currency: "INR",
      receipt: "order_" + Date.now(),
    };

    const order = await razorpay.orders.create(options);

    if (!order) return res.status(500).json({ message: "Razorpay order creation failed" });

    res.json(order);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to create payment order" });
  }
});

app.post("/api/payment/verify", auth, async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
    const expected = crypto.createHmac("sha256", process.env.RAZORPAY_SECRET)
      .update(razorpay_order_id + "|" + razorpay_payment_id)
      .digest("hex");
    if (expected !== razorpay_signature) return res.status(400).json({ message: "Payment verification failed" });
    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to verify payment" });
  }
});

/* ================= CHECKOUT ================= */
app.post("/api/checkout", auth, async (req, res) => {
  try {
    const { address, paymentId } = req.body;
    const user = await User.findById(req.user.id);

    if (!user.cart || user.cart.length === 0) {
      return res.status(400).json({ message: "Cart empty" });
    }

    // ✅ normalize cart → order products
    const products = user.cart.map(item => ({
      _id: item.productId,
      title: item.title,
      price: Number(item.price) || 0,
      quantity: Number(item.quantity) || 1
    }));

    const totalAmount = products.reduce(
      (sum, p) => sum + p.price * p.quantity,
      0
    );

    const order = await Order.create({
      userId: user._id,
      products,
      address,
      paymentId,
      totalAmount,
      status: "Processing"
    });

    // Credit supercoins
    const earnedCoins = Math.floor(totalAmount / 100);
    if (earnedCoins > 0) {
      user.supercoins += earnedCoins;
    }

    user.cart = [];
    await user.save();


    // Send order confirmation email using template
    const template = await EmailTemplate.findOne({ key: 'orderConfirmed', isActive: true });
    if (template) {
      const html = renderTemplate(template.html, {
        name: user.name,
        orderId: order._id.toString(),
        totalAmount: order.totalAmount
      });
      await sendEmail({
        to: user.email,
        subject: template.subject,
        html
      });
    }

    // Send SMS to admins
    await sendAdminSMS(`New order #${order._id} placed by ${user.name} for ₹${totalAmount}`);

    res.json(order);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to process checkout" });
  }
});


// supercoins---=============================================

app.patch("/api/admin/users/:id/supercoins", auth, adminAuth, async (req, res) => {
  try {
    const { amount, action } = req.body;
    // action = "add" | "deduct"

    if (!amount || amount <= 0)
      return res.status(400).json({ message: "Invalid amount" });

    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message: "User not found" });

    if (action === "add") {
      user.supercoins += amount;
    } else if (action === "deduct") {
      user.supercoins = Math.max(0, user.supercoins - amount);
    } else {
      return res.status(400).json({ message: "Invalid action" });
    }

    await user.save();

    res.json({
      success: true,
      supercoins: user.supercoins
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to update supercoins" });
  }
});


/* ================= ORDERS ================= */
app.get("/api/orders", auth, async (req, res) => {
  try {
    res.json(await Order.find({ userId: req.user.id }));
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to fetch orders" });
  }
});
app.get("/api/admin/orders", auth, adminAuth, async (req, res) => {
  try {
    const { search } = req.query;
    let filter = {};
    if (search) {
      filter.userId = { $regex: search, $options: 'i' };
    }
    res.json(await Order.find(filter).sort({ createdAt: -1 }).populate('userId', 'name email'));
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to fetch admin orders" });
  }
});

app.patch("/api/admin/orders/:id/status", auth, adminAuth, async (req, res) => {
  try {
    const { status } = req.body;

    const allowed = ["Pending", "Processing", "Confirmed", "Shipped", "Delivered"];
    if (!allowed.includes(status))
      return res.status(400).json({ message: "Invalid status" });

    const order = await Order.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    );

    if (!order) return res.status(404).json({ message: "Order not found" });

    // Send status update email if applicable (e.g., Shipped, Delivered)
    if (['Shipped', 'Delivered'].includes(status)) {
      const user = await User.findById(order.userId);
      if (user) {
        const key = status === 'Shipped' ? 'orderShipped' : 'orderDelivered';
        const template = await EmailTemplate.findOne({ key, isActive: true });
        if (template) {
          const html = renderTemplate(template.html, {
            name: user.name,
            orderId: order._id.toString(),
            status
          });
          await sendEmail({
            to: user.email,
            subject: template.subject,
            html
          });
        }
      }
    }

    res.json(order);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to update order status" });
  }
});



app.delete("/api/admin/orders/:id", auth, adminAuth, async (req, res) => {
  try {
    await Order.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to delete order" });
  }
});

/* ================= DASHBOARD STATS ================= */
app.get("/api/admin/stats", auth, adminAuth, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const totalOrders = await Order.countDocuments();
    const totalRevenue = await Order.aggregate([
      {
        $group: {
          _id: null,
          sum: { $sum: "$totalAmount" }
        }
      }
    ]);

    const pendingOrders = await Order.countDocuments({ status: "Pending" });
    res.json({
      totalUsers,
      totalOrders,
      totalRevenue: totalRevenue[0]?.sum || 0,
      pendingOrders
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to fetch stats" });
  }
});

/* ================= SERVER ================= */
// app.listen(5000, () => console.log("Server running → http://localhost:5000"));
module.exports = app;