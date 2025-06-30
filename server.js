const express = require("express");
const app = express();
const path = require("path");
const session = require("express-session");
const bcrypt = require("bcrypt");
const dotenv = require("dotenv");
const MongoStore = require("connect-mongo");

dotenv.config();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Specify the port to listen on
const port = 3000;
const host = "http://localhost:" + port;

// Start the server
app.listen(port, () => console.log("Server starting... on " + host));

let db;
const { MongoClient } = require("mongodb");

const client = new MongoClient(process.env.MONGO_URI);

async function connect() {
  try {
    const conn = await client.connect();
    db = await conn.db("session_test");
    //db = await conn.db("session_test");
  } catch (error) {
    console.log(error);
  }
  return;
}
connect();

// Middleware when user mkas a request it will create a session if there are none or changes has happend to the exsisting one  
app.use(
  session({
    secret: process.env.SESSION_KEY,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 1000 * 60 * 60, // 1 hour
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
);


app.get("/", async (req, res) => {
  const result = await connect();
  res.send(result);
});



//Register
app.get("/register", async (req, res) => {
  res.sendFile(path.join(__dirname, "routes", "register.html"));
});

app.post("/register", async (req, res) => {
  console.log("Received body:", req.body);

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



//Login
app.get("/login", async (req, res) => {
  res.sendFile(path.join(__dirname, "routes", "login.html"));
});

app.post("/login", async (req, res) => {
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
});
