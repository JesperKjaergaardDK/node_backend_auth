const express = require("express");
const app = express();

const path = require("path");
const bcrypt = require("bcrypt");
const dotenv = require("dotenv");

//Session
const session = require("express-session");
const MongoStore = require("connect-mongo");

//JWT
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

dotenv.config();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Specify the port to listen on
const port = 3000;
const host = "http://localhost:" + port;

// Start the server
app.listen(port, () => console.log("Server starting... on " + host));

const { MongoClient } = require("mongodb");

const client = new MongoClient(process.env.MONGO_URI);

let db;

async function connect() {
  try {
    const conn = await client.connect();
    //Depending what auth to test
    //db = await conn.db("jwt_test");
    db = await conn.db("session_test");
  } catch (error) {
    console.log(error);
  }
  return;
}
connect();

//session based
// Middleware when user mkas a request it will create a session if there are none or changes has happend to the exsisting one
/* app.use(
  session({
    secret: process.env.SESSION_KEY,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 1000 * 60, //1 min
      httpOnly: true,
      secure: false, // true in production with HTTPS
    },
    store: MongoStore.create({
      client: client,
      dbName: "session_test",
      collectionName: "sessions",
      ttl: 60 * 60, // 1 hour expiration
    }),
  })
); */

/* function sessionAuth(req, res, next) {
  if (req.session && req.session.userId) {
    console.log(req.session);
    console.log(req.session.userId);
    
    next(); // Session is valid
  } else {
    res.status(401).send("Unauthorized: No session");
  }
} */

function JWTAuth(req, res, next) {
  try {
    const token = req.headers.authorization.split(" ")[1]; // "Bearer <token>"
    if (!token) throw new error(500);

    const decode = jwt.verify(token, process.env.JWT_SECRET);
    console.log("this decode: " + decode);
    if (!decode) throw new error(500);

    next();
  } catch (error) {
    console.log(error);
    res.sendFile(path.join(__dirname, "routes", "error.html"));
  }
}

//Homepage
app.get("/", sessionAuth, async (req, res) => {
  const result = await db.collection("users").find().toArray();
  res.send(result);
});

//Register
app.get("/register", async (req, res) => {
  res.sendFile(path.join(__dirname, "routes", "register.html"));
});

//Login
app.get("/login", async (req, res) => {
  res.sendFile(path.join(__dirname, "routes", "login.html"));
});

//Register user for both auth
app.post("/register", async (req, res) => {
  const { username, email, password, passwordConfirm } = req.body;
  if (!username || !email || !password || !passwordConfirm) {
    return res.status(400).send("Missing username or password");
  }

  if (password !== passwordConfirm) {
    return res.status(400).send("The passwords are not the same");
  }

  //hashes the password with a salt of 10
  const hash = await bcrypt.hash(password, 10);

  try {
    const coll = db.collection("users");
    await coll.insertOne({ username, email, password: hash });
    res.send("User registered");
  } catch (err) {
    console.error(err);
    res.status(500).send("Error occurred with registration of user");
  }
});





//Session based authenticaiton
/* app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).send("Missing email or password");
  }

  try {
    //Checks if the email exist
    const coll = db.collection("users");
    const user = await coll.findOne({ email });
    if (!user) return res.status(401).send("Invalid email or password");

    //cant decrypt a hash the only way is to compare
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).send("Invalid email or password");

    // Save user data in session
    // Express-session also creates the cookie with a deafult name and the session id
    req.session.userId = user._id;
    req.session.username = user.username;

    res.send(`Logged in as ${user.username}`);

  } catch (err) {
    console.error(err);
    res.status(500).send("Login error");
  }
}); */




//JWT based authenticaiton

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).send("Missing email or password");
  }

  try {
    const coll = db.collection("users");
    const user = await coll.findOne({ email });
    if (!user) return res.status(401).send("Invalid email or password");

    //Signed jwt of token and refresh token
    const token = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    const refreshToken = jwt.sign(
      { id: user._id, email: user.email },
      process.env.RESET_SECRET,
      { expiresIn: "7d" }
    );

    //send the refresh secure in the db
    await db
      .collection("tokens")
      .insertOne({ userId: user._id, token: refreshToken });

    //Sends the refresh token to a httponly cookie to protect agenst XSS attacks
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      sameSite: "strict",
      secure: false,
    });

    res.send(token);

  } catch (err) {
    console.error(err);
    res.status(500).send("Login error");
  }
});
