import express from 'express'
import cors from 'cors'
import 'dotenv/config'
import mongoose from 'mongoose'
import bcrypt from 'bcrypt'

const url = 'mongodb://127.0.0.1:27017/Test'
let statusdb = null

mongoose
  .connect(url, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log('Połączono z bazą danych MongoDB')
    statusdb = 'Good'
  })
  .catch((error) => {
    statusdb = 'Bad'
    console.error('Błąd połączenia z MongoDB:', error)
  })

const ip = '192.168.0.101'
const port = 3000

const app = express()
app.use(cors())
app.use(express.json())

const userSchema = new mongoose.Schema({
  username: String,
  password: String,
})

const User = mongoose.model('users', userSchema)

app.post('/login', async (req, res) => {
  const { username, password } = req.body

  const user = await User.findOne({ username })

  if (user) {
    bcrypt.compare(password, user.password, (err, result) => {
      if (err) {
        console.error(err)
        return res.json({ error: err })
      } else if (result) {
        return res.json({ logged: true })
      } else {
        return res.json({ error: 'Nieprawidłowe hasło!' })
      }
    })
  } else {
    return res.json({ error: 'Nieprawidłowa nazwa użytkownika lub hasło.' })
  }
})

app.get('/checkConnect', (req, res) => {
  const status = { statusServer: 'Good', statusDB: statusdb }
  res.send(status)
})

app.listen(port, () => {
  console.log(`Server listening on port ${port}.`)
})
