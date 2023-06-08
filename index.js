const express = require('express');
const cors = require('cors');
const app = express()
const jwt = require('jsonwebtoken');
require('dotenv').config()
const stripe = require('stripe')(process.env.PAYMENT_SECRET_KEY)
const port = process.env.PORT || 5000;

//middleware
app.use(cors())
app.use(express.json())

const varifyJWT = (req, res, next) => {
  const authorization = req.headers.authorization;
  if (!authorization) {
    return res.status(401).send({ error: true, message: 'unauthorized access' })
  }
  //bearer token
  const token = authorization.split(' ')[1];
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).send({ error: true, message: 'unauthorized token' })
    }
    req.decoded = decoded;
    next()
  })

}


const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.cgmlfql.mongodb.net/?retryWrites=true&w=majority`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    // await client.connect();

    const usersCollection = client.db('tufaelDb').collection('users')
    const menuCollection = client.db('tufaelDb').collection('menu')
    const reviewCollection = client.db('tufaelDb').collection('reviews')
    const cartCollection = client.db('tufaelDb').collection('carts')
    const paymentCollection = client.db('tufaelDb').collection('payments')

    //JWT: related apis
    app.post('/jwt', (req, res) => {
      const user = req.body;
      const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '72h' })
      res.send({ token })
    })

    //warning: use varifyJWT before using verifyAdmin
    const varifyAdmin = async (req, res, next) => {
      const email = req.decoded.email;
      const query = { email: email }
      const user = await usersCollection.findOne(query)
      if (user?.role !== 'admin') {
        return res.status(403).send({ error: true, message: 'forbidden message' })
      }
      next()
    }

    /**
     * 0. do not show secure links to those who should not see the links
     * 1. use jwt token: varifyToken
     */

    //users related apis
    app.get('/users', varifyJWT, varifyAdmin, async (req, res) => {
      const result = await usersCollection.find().toArray()
      res.send(result)
    })

    app.post('/users', varifyJWT, varifyAdmin, async (req, res) => {
      const user = req.body;
      const query = { email: user.email }
      const existingUser = await usersCollection.findOne(query)
      if (existingUser) {
        return res.send({ message: 'user already exists' })
      }
      const result = await usersCollection.insertOne(user)
      res.send(result)
    })

    //security layer: varifyJWT
    //email same
    //check admin
    app.get('/users/admin/:email', varifyJWT, async (req, res) => {
      const email = req.params.email;
      // console.log(email, req.decoded);

      if (req.decoded.email !== email) {
        return res.send({ admin: false })
      }
      const query = { email: email }
      const user = await usersCollection.findOne(query)
      const result = { admin: user?.role === 'admin' }
      // console.log(result);
      res.send(result)
    })

    app.patch('/users/admin/:id', async (req, res) => {
      const id = req.params.id;
      const filter = { _id: new ObjectId(id) }
      const updatedDoc = {
        $set: {
          role: 'admin'
        },
      };
      const result = await usersCollection.updateOne(filter, updatedDoc)
      res.send(result)
    })

    //menu related apis
    app.get('/menu', async (req, res) => {
      const result = await menuCollection.find().toArray()
      res.send(result)
    })

    app.post('/menu', async (req, res) => {
      const newItem = req.body;
      const result = await menuCollection.insertOne(newItem)
      res.send(result)
    })

    app.delete('/menu/:id', varifyJWT, varifyAdmin, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) }
      const result = await menuCollection.deleteOne(query)
      res.send(result)
    })

    //reviews related apis
    app.get('/reviews', async (req, res) => {
      const result = await reviewCollection.find().toArray()
      res.send(result)
    })

    //cart collection apis
    app.get('/carts', varifyJWT, async (req, res) => {
      const email = req.query.email;
      // console.log(email);
      if (!email) {
        return res.send([]);
      }

      const decodedEmail = req.decoded.email;
      if (email !== decodedEmail) {
        return res.status(403).send({ error: true, message: 'forbidden access' })
      }
      const query = { email: email }
      const result = await cartCollection.find(query).toArray()
      res.send(result)
    })

    app.post('/carts', async (req, res) => {
      const item = req.body;
      const result = await cartCollection.insertOne(item)
      res.send(result)
    })


    app.delete('/carts/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) }
      const result = await cartCollection.deleteOne(query)
      res.send(result)
    })

    //create-payment-intent
    app.post('/create-payment-intent', varifyJWT, async (req, res) => {
      const { price } = req.body;
      // console.log(req.body);
      const amount = parseInt(price * 100)
      // console.log(price, amount);
      const paymentIntent = await stripe.paymentIntents.create({
        amount: amount,
        currency: 'usd',
        payment_method_types: ['card']
      })
      res.send({
        clientSecret: paymentIntent.client_secret
      })
    })

    //payment related api
    app.post('/payments', varifyJWT, async (req, res) => {
      const payment = req.body;
      const insertResult = await paymentCollection.insertOne(payment)

      const query = { _id: { $in: payment.cartItems.map(id => new ObjectId(id)) } }
      const deleteResult = await cartCollection.deleteMany(query)

      res.send({ insertResult, deleteResult })
    })


    app.get('/admin-stats', varifyJWT, varifyAdmin, async (req, res) => {
      const users = await usersCollection.estimatedDocumentCount();
      const products = await menuCollection.estimatedDocumentCount();
      const orders = await paymentCollection.estimatedDocumentCount();

      //best way to get sum of a price field is to use group and sum operation
      // collection.aggregate([
      //   { $group: { _id: null, total: { $sum: `$${fieldName}` } } }
      // ]).toArray(function(err, result) {
      //   if (err) {
      //     console.error('Error executing the query:', err);
      //     return;
      //   }

      const payments = await paymentCollection.find().toArray()
      const revenue = payments.reduce((sum, payment) => sum + payment.price, 0)

      res.send({
        users,
        products,
        orders,
        revenue
      })
    })

    /**
     * BANGLA SYSTEM(second best system)
     * ---------------------------------
     * 1. load all payments.
     * 2. for each payment, get the menuItems array.
     * 3. for each item in the menuItems in the array get the menuItem from the menu collection.
     * 4. put them in an array: allOrdersItems.
     * 5. separate allOrderedItems by category using filter
     * 6. now get the quantity by using length: pizzas.length;
     * 7. for each category use reduce to get the total amount spent on this category.
     */
    app.get('/order-stats', varifyJWT, varifyAdmin, async(req, res) =>{
      const pipeline = [
        {
          $lookup:{
            from:'menu',
            localField: 'menuItems',
            foreignField: '_id',
            as: 'menuItemsData'
          }
        },
        {
          $unwind: '$menuItemsData'
        },
        {
          $group:{
            _id: '$menuItemsData.category',
            count: {$sum: 1},
            total: {$sum: '$menuItemsData.price'}
          }
        },
        {
          $project: {
            category: '$_id',
            count: 1,
            total: {$round: ['$total', 2]},
            _id: 0
          }
        }
      ];

      const result = await paymentCollection.aggregate(pipeline).toArray()
      res.send(result)
    })


    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.get('/', (req, res) => {
  res.send('server is running');
})

app.listen(port, () => {
  console.log(`super resturant ${port}`);
})

/**
 * naming convention
 * 1. users: userCollection
 * app.get('/users')
 * app.get('/users/:id')
 * app.post('/users')
 * app.patch('/users/:id')
 * app.put('/users/:id')
 * app.delete('/users/:id')
 */