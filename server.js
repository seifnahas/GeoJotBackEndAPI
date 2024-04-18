// server.js

const PasswordValidator = require('password-validator');

// Create a password schema
const passwordSchema = new PasswordValidator();

// Define password rules
passwordSchema
  .is().min(8)  
  .has().uppercase()  
  .has().lowercase()  
  .has().digits();  


const express = require('express');
const connectToDatabase = require('./db');
const { MongoClient, ObjectId } = require('mongodb');
const bcrypt = require('bcrypt');
const cors = require('cors');
const axios = require('axios'); 
const qs = require('querystring');  
require('dotenv').config();


// Multer and Multer-S3 for handling file uploads to AWS S3 (pictures)
const multer = require('multer');
const multerS3 = require('multer-s3');
const { S3Client, ListObjectsCommand } = require("@aws-sdk/client-s3");
const { profile } = require('console');


const app = express();
const port = process.env.PORT || 3000; 





app.use(express.json());
app.use(cors());

// Initialise AWS S3 Client
const s3Client = new S3Client({
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
  region: process.env.AWS_REGION
});


console.log("AWS_ACCESS_KEY_ID:", process.env.AWS_ACCESS_KEY_ID);
console.log("AWS_SECRET_ACCESS_KEY:", process.env.AWS_SECRET_ACCESS_KEY);
console.log("AWS_REGION:", process.env.AWS_REGION);



// multer uses multer-s3 to store files in S3
const uploadPinImages = multer({
  storage: multerS3({
    s3: s3Client,
    bucket: process.env.S3_BUCKET_NAME,
    key: function (req, file, cb) {
      cb(null, `pins/${Date.now()}_${file.originalname}`);
    }
  })
});

const uploadProfilePicture = multer({
  storage: multerS3({
    s3: s3Client,
    bucket: 'geojot',
    key: function (req, file, cb) {
      cb(null, `profile-pictures/${Date.now()}_${file.originalname}`);
    }
  })
})

// User registration route
app.post('/api/register', async (req, res) => {
  const { email, username, password } = req.body;
  const defaultProfilePicUrl = 'https://geojot.s3.eu-west-1.amazonaws.com/profile-pictures/default-profile-pic.jpg'; // URL of the default profile


  // Validate the password using the schema
  const passwordValidation = passwordSchema.validate(password, { list: true });

  if (username.length < 4 || username.length > 20) {
    return res.status(400).json({ error: 'Username must be between 4 and 20 characters' });
  }

  if (passwordValidation.length > 0) {
    return res.status(400).json({ error: 'Password does not meet criteria.', failedRules: passwordValidation });
  } //password must have at least 8 characters, 1 uppercase, 1 lowercase, 1 digit

  try {
    const client = await connectToDatabase();  
    const db = client.db();  

    // Check if the user already exists in the database
    const existingUser = await db.collection('users').findOne({ username });
    if (existingUser) {
      return res.status(400).json({ error: 'Username already exists.' });
    }

    //Check if the email already exists in the database
    const existingEmail = await db.collection('users').findOne({ email });
    if (existingEmail) {
      return res.status(400).json({ error: 'Email already exists.' });
    }

    // Hash the password before storing it in the database
    const hashedPassword = await bcrypt.hash(password, 10);

    await db.collection('users').insertOne({
      email,
      username,
      password: hashedPassword,
      profilePic: defaultProfilePicUrl,
    });

    res.status(201).json({ message: 'User registered successfully' });
    console.log('User registered:', { email, username });
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(500).json({ error: 'Internal server error, from server.js' });
  }
});

// User login route
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const client = await connectToDatabase();
    const db = client.db();



    // Find the user by username
    const user = await db.collection('users').findOne({ username });
    if (!user) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    // Compare the provided password with the hashed password stored in the database
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    // If the username and password are correct, send a success response
    res.status(200).json({ message: 'Login successful', user: { username: user.username, email: user.email } });
    console.log('User logged in:', { username: user.username });
  } catch (error) {
    console.error('Error logging in:', error);
    res.status(500).json({ error: 'Internal server error, from server.js' });
  }
});

// Save pins and respective media files
app.post('/api/pins', async (req, res) => {
  const { position, username, name, notes, music, selectedSongDetails, mediaFiles } = req.body;

  try {
    const client = await connectToDatabase();
    const db = client.db();

    const result = await db.collection('pins').insertOne({
      position,
      username,
      name,
      notes,
      music,
      selectedSongDetails,
      mediaFiles,
      createdAt: new Date()
    });

    const insertedId = result.insertedId;
    res.status(201).json({ _id: insertedId, message: 'Pin saved successfully' });
  } catch (error) {
    console.error('Error saving pin:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


// Update Pin Details
app.put('/api/pins/:id', uploadPinImages.array('mediaFiles', 9), async (req, res) => {
  const { id } = req.params;
  let { name, notes, music, selectedSongDetails } = req.body;

  if (typeof selectedSongDetails === 'string') {
    selectedSongDetails = JSON.parse(selectedSongDetails);
  }

  const newMediaFilesUrls = req.files.map(file => file.location);

  if(req.files.length > 9) {
    return res.status(400).json({ error: 'Exceeded the limit of 9 images.' });
  }

  try {
    const client = await connectToDatabase();
    const db = client.db();

    const existingPin = await db.collection('pins').findOne({ _id: new ObjectId(id) });
    const existingMediaFiles = existingPin ? existingPin.mediaFiles || [] : [];
    
    const updatedMediaFiles = [...existingMediaFiles, ...newMediaFilesUrls];

    // Construct the update data
    const updateData = {
      ...(name && { name }),
      ...(notes && { notes }),
      ...(music && { music }),
      ...(selectedSongDetails && { selectedSongDetails }),  
      ...(updatedMediaFiles.length > 0 && { mediaFiles: updatedMediaFiles }),
    };

    const result = await db.collection('pins').updateOne(
      { _id: new ObjectId(id) },
      { $set: updateData }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ error: 'Pin not found' });
    } else {
      res.status(200).json({ message: 'Pin updated successfully' });
    }
  } catch (error) {
    console.error('Error updating pin:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


// Retrieve pins route
app.get('/api/pins', async (req, res) => {
  const { username } = req.query;

  try {
    const client = await connectToDatabase();
    const db = client.db();
    const pins = await db.collection('pins').find({ username }).toArray(); // Fetch pins for the specified user
    res.json(pins);
  } catch (error) {
    console.error('Error retrieving pins:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete Pins
app.delete('/api/pins/:id', async (req, res) => {
  const { id } = req.params;

  try {

    const client = await connectToDatabase();
    const db = client.db();

    const result = await db.collection('pins').deleteOne({ _id: new ObjectId(id) });

    if (result.deletedCount === 1) {
      res.json({ message: 'Pin successfully deleted' });
    } else {
      res.status(404).json({ message: 'Pin not found' });
    }
  } catch (error) {
    console.error('Error deleting pin:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Fetch a specific pin's details by ID
app.get('/api/pins/details/:id', async (req, res) => {
  const { id } = req.params; 

  try {
    const client = await connectToDatabase();
    const db = client.db();

    const pinDetails = await db.collection('pins').findOne({ _id: new ObjectId(id) });

    if (!pinDetails) {
      return res.status(404).json({ error: 'Pin not found' });
    }

    // If pin is found, send back its details
    res.status(200).json(pinDetails);

  } catch (error) {
    console.error('Error fetching pin details:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Fetch recent pins for a specific user
app.get('/api/pins/recent', async (req, res) => {
  const { username } = req.query;

  try {
    const client = await connectToDatabase();
    const db = client.db();
    const recentPins = await db.collection('pins').find({ username }).sort({ createdAt: -1 }).limit(4).toArray();
    res.json(recentPins);
  } catch (error) {
    console.error('Error retrieving recent pins:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

//Get spotify access token
async function getSpotifyAccessToken() {
  const authOptions = {
    method: 'post',
    url: 'https://accounts.spotify.com/api/token',
    headers: {
      'Authorization': 'Basic ' + Buffer.from(`${process.env.SPOTIFY_CLIENT_ID}:${process.env.SPOTIFY_CLIENT_SECRET}`).toString('base64'),
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    data: qs.stringify({ grant_type: 'client_credentials' })
  };

  try {
    const response = await axios(authOptions);
    return response.data.access_token;
  } catch (error) {
    console.error("Can't obtain token", error);
    return null;
  }
}

// Endpoint to search songs on Spotify
app.get('/api/spotify/search', async (req, res) => {

  console.log("Fetching music......")
  const accessToken = await getSpotifyAccessToken();
  if (!accessToken) {
    return res.status(500).json({ message: "Can't obtain token" });
  }

  const { query } = req.query;
  if (!query) {
    return res.status(400).json({ message: 'Search query is required' });
  }

  try {
    const searchResponse = await axios.get(`https://api.spotify.com/v1/search`, {
      headers: {
        'Authorization': `Bearer ${accessToken}`
      },
      params: {
        q: query,
        type: 'track',
        limit: 10 
      }
    });

    res.json(searchResponse.data);
  } catch (error) {
    console.error("Error searching Spotify:", error);
    res.status(500).json({ message: 'Failed to perform search on Spotify.', error: error.response.data });
  }
});

app.get('/api/places/search', async (req, res) => {
  const { query } = req.query;
  try {
    const response = await axios.get(`https://maps.googleapis.com/maps/api/place/autocomplete/json?input=${query}&key=${process.env.GOOGLE_KEY}`);
    if (response.data && response.data.status === 'OK') {
      res.json(response.data.predictions);
    } else {
      res.status(404).json({ message: 'No places found' });
    }
  } catch (error) {
    console.error('Error searching places:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/places/details/:placeId', async (req, res) => {
  const { placeId } = req.params;
  try {
    const response = await axios.get(`https://maps.googleapis.com/maps/api/place/details/json?placeid=${placeId}&key=${process.env.GOOGLE_KEY}`);
    if (response.data && response.data.status === 'OK') {
      const location = response.data.result.geometry.location;
      res.json({ lat: location.lat, lng: location.lng });
    } else {
      res.status(404).json({ message: 'Place details not found' });
    }
  } catch (error) {
    console.error('Error fetching place details:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});




//Endpoit used to search users
app.get('/api/users/search', async (req, res) => {
  const { query } = req.query;
  try {
    const client = await connectToDatabase();
    const db = client.db();
    const users = await db.collection('users').find({ username: { $regex: query, $options: "i" } }).toArray();

    // Map through the users to ensure each user has a profilePic property.
    const usersWithProfilePics = users.map(user => {
      return {
        ...user,
        profilePic: user.profilePic || 'https://geojot.s3.eu-west-1.amazonaws.com/profile-pictures/default-profile-pic.jpg'
      };
    });

    res.json(usersWithProfilePics);
  } catch (error) {
    console.error('Error searching users:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});



// Toggle pin like
app.post('/api/pins/:id/toggle-like', async (req, res) => {
  const { id } = req.params;
  const { userId } = req.body;

  try {
    const client = await connectToDatabase();
    const db = client.db();

    const pin = await db.collection('pins').findOne({ _id: new ObjectId(id) });

    // Check if the user has already liked the pin
    const hasLiked = pin.likes && pin.likes.includes(userId);

    // Update pin - add or remove user ID from likes array
    const update = hasLiked
      ? { $pull: { likes: userId } }
      : { $addToSet: { likes: userId } };

    await db.collection('pins').updateOne({ _id: new ObjectId(id) }, update);

    res.json({ message: 'Like toggled' });
  } catch (error) {
    console.error('Error toggling pin like:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});



// Endpoint to fetch likes for a specific pin
app.get('/api/pins/:id/likes', async (req, res) => {
  const { id } = req.params;

  try {
    const client = await connectToDatabase();
    const db = client.db();

    const pin = await db.collection('pins').findOne({ _id: new ObjectId(id) }, { projection: { likes: 1 } });
    if (!pin) {
      return res.status(404).json({ message: 'Pin not found' });
    }

    // Send back the likes array; if it doesn't exist, send an empty array
    res.json({ likes: pin.likes || [] });
  } catch (error) {
    console.error('Error fetching likes:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Endpoint to add a collaborator to a pin
app.post('/api/pins/:id/collaborators', async (req, res) => {
  const { collaboratorUsername } = req.body;
  const pinId = req.params.id;

  try {
    const client = await connectToDatabase();
    const db = client.db();

    const userExists = await db.collection('users').findOne({ username: collaboratorUsername });
    if(!userExists) {
      return res.status(404).json({ message: 'User not found'});
    }

    const pin = await db.collection('pins').findOne({ _id: new ObjectId(pinId) });
    if (!pin) {
      return res.status(404).json({ message: 'Pin not found'});
    }

    const result = await db.collection('pins').updateOne(
      { _id: new ObjectId(pinId) },
      { $addToSet: { collaborators: collaboratorUsername } }
    );

    if(result.modifiedCount === 1) {
      res.status(200).json({ message: 'Collaborator added successfully' });
    } else {
      res.status(400).json({ message: 'Failed to add collaborator' });
    }
  } catch (error) {
    console.error('Error adding collaborator:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Endpoint used to follow a user
app.post('/api/users/:username/follow', async (req, res) => {
  const { username } = req.params;
  const { follower } = req.body;

  // Prevent users from following themselves
  if (username === follower) {
    return res.status(400).json({ message: 'Users cannot follow themselves' });
  }

  try {
    const client = await connectToDatabase();
    const db = client.db();

    // Add the follower's username to the user's followers array if not already present
    const result = await db.collection('users').updateOne(
      { username: username },
      { $addToSet: { followers: follower } }  
    );

    if (result.modifiedCount === 0) {
      return res.status(404).json({ message: 'User not found or already followed' });
    }
 
    res.status(200).json({ message: 'Successfully followed user' });
  } catch (error) {
    console.error('Error following user:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Endpoint used to unfollow a user
app.post('/api/users/:username/unfollow', async (req, res) => {
  const { username } = req.params;
  const { follower } = req.body;

  try {
    const client = await connectToDatabase();
    const db = client.db();

    const result = await db.collection('users').updateOne(
      { username: username },
      { $pull: { followers: follower } } // $pull removes the follower from the array
    );

    if (result.modifiedCount === 0) {
      return res.status(404).json({ message: 'User not found or not followed' });
    }

    res.status(200).json({ message: 'Successfully unfollowed user' });
  } catch (error) {
    console.error('Error unfollowing user:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

//Fetches the pin details by user
app.get('/api/users/:username/details', async (req, res) => {
  const { username } = req.params;

  try {
    const client = await connectToDatabase();
    const db = client.db();
    
    const user = await db.collection('users').findOne({ username: username });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.status(200).json(user);
  } catch (error) {
    console.error('Error fetching user details:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Endpoint to update profile picture for current user
app.put('/api/users/:username/profile-picture', uploadProfilePicture.single('profilePic'), async (req, res) => {
  const { username } = req.params;
  console.log('Updating profile picture for', username);

  if (!req.file) {
    console.log('No file uploaded, returning 400');
    return res.status(400).send('No file uploaded.');
  }

  const profilePic = req.file.location;
  console.log('Profile picture URL is', profilePic);

  try {
    const client = await connectToDatabase();
    const db = client.db();

    // Update the user's profile picture URL in the database
    const result = await db.collection('users').updateOne(
      { username: username },
      { $set: { profilePic: profilePic } }
    );

    if (result.modifiedCount === 0) {
      console.log('User not found, returning 404');
      return res.status(404).json({ message: 'User not found' });
    }

    console.log('Successfully updated profile picture for', username);
    res.json({ message: 'Profile picture updated successfully', profilePic: profilePic });
  } catch (error) {
    console.error('Error updating profile picture:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Endpoint to change password
app.post('/api/users/:username/change-password', async (req, res) => {
  const { username } = req.params;
  const { newPassword } = req.body;

  console.log('Changing password for', username);

  // Validate the new password
  const passwordValidation = passwordSchema.validate(newPassword, { list: true });
  if (passwordValidation.length > 0) {
    // If the password doesn't meet the criteria, send an error response
    return res.status(400).json({ 
      error: 'Password does not meet criteria.',
      additionalInfo: 'Password must have at least 8 characters, uppercase and lowercase letters, and contains digits.',
      failedRules: passwordValidation
    });
  }

  try {
    const client = await connectToDatabase();
    const db = client.db();

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await db.collection('users').updateOne({ username }, { $set: { password: hashedPassword } });

    res.json({ message: 'Password updated successfully.' });
  } catch (error) {
    console.error('Error changing password:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Endpoint to delete account and all associated data
app.delete('/api/users/:username', async (req, res) => {
  const { username } = req.params;

  try {
    const client = await connectToDatabase();
    const db = client.db();

    const session = client.startSession();
    await session.withTransaction(async () => {
      // Delete user's pins
      await db.collection('pins').deleteMany({ username }, { session });
      
      // Remove user from others' followers lists
      await db.collection('users').updateMany({}, { $pull: { followers: username } }, { session });

      // Remove the people they follow
      await db.collection('users').updateOne({ username }, { $set: { following: [] } }, { session });

      // Delete the user account
      await db.collection('users').deleteOne({ username }, { session });
    });

    session.endSession();

    res.json({ message: 'Account deleted successfully.' });
  } catch (error) {
    console.error('Error deleting account:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Endpoint to remove images
app.patch('/api/pins/:id/remove-image', async (req, res) => {
  const { id } = req.params;
  const { imageUrl } = req.body;

  if (!imageUrl) {
    return res.status(400).json({ error: 'No image URL provided' });
  }

  try {
    const client = await connectToDatabase();
    const db = client.db();

    const result = await db.collection('pins').updateOne(
      { _id: new ObjectId(id) },
      { $pull: { mediaFiles: imageUrl } }
    );

    if (result.modifiedCount === 0) {
      return res.status(404).json({ error: 'Image not found or pin not found' });
    } else {
      res.status(200).json({ message: 'Image removed successfully' });
    }
  } catch (error) {
    console.error('Error removing image from pin:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


// Start the server
async function startServer() {
  try {
    await connectToDatabase();
    app.listen(port, () => {
      console.log(`Server running on http://localhost:${port}`);
      console.log("access", process.env.AWS_ACCESS_KEY_ID)
      console.log("secret", process.env.AWS_SECRET_ACCESS_KEY)
    });
  } catch (error) {
    console.error("Error starting server:", error);
  }
}



startServer();