import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import dotenv from "dotenv/config";
import session from "express-session"; // Package import
import bcrypt from "bcrypt";
import { Strategy } from "passport-local"; // Strategy for Passport JS
import GoogleStrategy from "passport-google-oauth2"; // Google OAuth Package
import passport from "passport"; // Passport package

const app = express();
const port = 3000;

const saltRounds = 10; // Define total rounds of salt to be applied to the password

const db = new pg.Client({
  database: process.env.DATABASE,
  port: process.env.PORT,
  host: process.env.HOST,
  password: process.env.PASSWORD,
  user: process.env.USER
});

db.connect();

async function saveDetails(name, pass) {
  try {
    const result = await db.query("INSERT INTO users(username, password) VALUES ($1, $2) RETURNING *;",[name, pass]);
    const details = result.rows[0];
    console.log(details);
    return details;
    

  } catch(error) {
    if(error.code == 23505) {
      console.log("Please register with an Unique Email ID");
    } else {
    console.log(error.code);
    }
  } 

}

async function checkDetails(name) {
  const query = await db.query("SELECT * FROM users WHERE username=$1", [name]);
  return query.rows[0];
}

async function addSecret(email, secret) {
  const query = await db.query("SELECT user_id FROM users WHERE username=$1", [email]);
  if(query.rows[0] == undefined){
    console.log("No user found");
    return false;
  } else {
    const insertSecret = await db.query("UPDATE users SET secret=$1 WHERE user_id=$2", [secret, query.rows[0].user_id]);
    console.log("Secret submitted successfully");
    return true;
  }
}

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

// USE SESSION MIDDLEWARE BEFORE PASSPORT JS
app.use(session({                   // Session Middleware
  secret: process.env.SECRET,  // Secret Key
  resave: false,  // Wanna save the session details to the database?
  saveUninitialized: true, // Wanna save uninitialized session data?
  cookie: {
    maxAge:  1000 * 60 * 60 * 24, // Sets the validity of cookie in milli-seconds 1000(ms) * 60(s) * 60(m) * 24(h)
  }
}))

app.use(passport.initialize());
app.use(passport.session());

app.get("/secrets", async(req, res) => {
  console.log(req.user); // To see the session details stored
  if(req.isAuthenticated()) {  // Returns true if the user is authenticated
    const result = await checkDetails(req.user.username);
    let secretText = result.secret == undefined ? "No secrets published by you" : result.secret;
  res.render("secrets.ejs", {secret: secretText});
  } else {
    res.redirect("/login");
  }
})

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

// API endpoint to access Google OAuth
app.get("/auth/google", passport.authenticate("google", {  // Authenticate with "google" strategy
  scope: ["profile", "email"] // Access scope (can only access profile, email as of now)
}))

app.get("/auth/google/secrets", passport.authenticate("google", { // GET route to secrets after Google OAuth
  successRedirect: "/secrets",  // Redirect route after successful authentication
  failureRedirect: "/login" // Redirect after failed authentication
}))

app.get("/logout", (req, res) => { // GET route to perform Log Out
  req.logout((err) => { // logout(callback()) method that performs logout
    if(err) { // If there's an error
      console.log(err);
    } else {  // If no error, redirect to home page
      res.redirect("/");
    }
  })
}); // API route to do Log Out

app.get("/submit", (req, res) => { // API route to render Secret Submission page
  try{
    if(req.isAuthenticated()) { // It can only be viewed if the user is authenticated
      console.log("Authenticated");
      res.render("submit.ejs");
    } else {
      res.redirect("/login"); // Otherwise, redirect to login page
    }
  }
  catch(err) {
    console.log(err);
  }
})

app.post("/register", async (req, res) => {
  bcrypt.hash(req.body.password, saltRounds, async(err, hash) => {  // bcrypt.hash(data_string, total_salt_rounds, callback_function(error, hash))
    const authorized = await saveDetails(req.body.username, hash);
    req.logIn(authorized, (err) => {  // Logins after registration. logIn(session_data, error_callback())
      console.log(err);
      res.redirect("/secrets");
    })
  })
});

app.post("/login", passport.authenticate("local", { // passport.authenticate(strategy_to_login, options)
  successRedirect: "/secrets",    // Redirects when authentication is successful
  failureRedirect: "/login" // Redirects when authentication is failed
}));

app.post("/submit", async(req, res) => { // POST route to update the Secret submission in the Database
  try{
    if(req.isAuthenticated()) { // This can only be donw if the user is authenticated
      const secretText = req.body.secret; // Get hold of secret Text
      console.log("Authenticated");
      const updateStatus = await addSecret(req.user.username, secretText); // Calling method to update Secret. Returns status as true, false
      if(updateStatus) {  // If successfully updated, redirect to secrets page
        res.redirect("/secrets");
      } else {
        res.redirect("/");  // Else , redirect to home page
      }
    } else {
      res.redirect("/login"); // If not authenticated, redirect to login page
    }
  }
  catch(err) {
    console.log(err);
  }
})

// Use this just before listen()
// Arguments inside verify() should have same name as that of the name of the input fields
// This is a middleware for checking authentication during browsing
passport.use(new Strategy(async function verify(username, password, cb) { // cb => Callback function
  console.log(username);

  const registeredDetails = await checkDetails(username);

  bcrypt.compare(password, registeredDetails.password, (err, result) => { // bcrypt.compare(entered_data, saved_data, callback(error, bool_result))
    if(err) {console.log(err); return cb(err); }   // Handling Errors and Callback err to the session
    else {
      if(result) {
        console.log("You are authenticated and authorized");
        return cb(null, registeredDetails); // cb(error, result)
      } else {
        console.log("Unauthorized User. Please Register with 'Register' button");
        return cb(null, false); // Make isAuthenticated() false
      }
    }
  } )

}))

// Define this after local strategy
passport.use("google", new GoogleStrategy(  // Defining Google OAuth Middleware, "google" is the name of the Authentication Strategy
  {
    clientID: process.env.CLIENT_ID,  // Our App's Client ID
    clientSecret: process.env.CLIENT_SECRET, // Our App's Client Secret
    callbackURL: "http://localhost:3000/auth/google/secrets", // Redirect URL after successful Authentication
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo" // API URL to access User Profile Information
  },
  async(accessToken, refreshToken, profile, cb) => { // cb => Callback function, Asynchronous method to get hold of access token, refresh token, profile data etc
    
    try {
      const result = await checkDetails(profile.email); // Checking whether User's credentials are already present in our database
      console.log(result);
      if(result == undefined) {
        const newUser = await saveDetails(profile.email, "google"); // If no results, save it in our database
        cb(null, newUser); // Updating callback with new User details
      } else {
        // If the user already exists
        cb(null, result); // Updating callback with Query results

      }
    } catch(error) {
      cb(error);
    }

  }
))

// After defining Strategy

passport.serializeUser((user, cb) => {    // Saves the session info in local storage
  cb(null, user); // cb(error, results)
})

passport.deserializeUser((user, cb) => {  //Helps us to access the saved details
  cb(null, user); // cb(error, results)
})

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
