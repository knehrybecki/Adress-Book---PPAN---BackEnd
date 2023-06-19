import * as dotenv from 'dotenv'
dotenv.config()
import express from 'express'
import cors from 'cors'
import mongoose from 'mongoose'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
const url = 'mongodb://127.0.0.1:27017/AdressBook'
let statusdb = null

mongoose
  .connect(url, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    console.log('Connected to the MongoDB database')
    statusdb = 'Good'
  })
  .catch((error) => {
    statusdb = 'Bad'
    console.error('Error connecting to MongoDB:', error)
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

const groupSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    unique: true,
  },
})
const contactSchema = new mongoose.Schema({
  firstName: {
    type: String,
    required: true,
  },
  lastName: String,
  companyName: String,
  positionInCompany: String,
  email: String,
  phoneMobile: {
    type: Number,
    required: true,
  },
  phoneHome: String,
  group: {
    type: String,
    ref: 'groups',
  },
  groupName: String,
})

const Group = mongoose.model('groups', groupSchema)
const Contact = mongoose.model('contacts', contactSchema)

const secretKey = process.env.JWT_SECRET

const username = process.env.DEFAULT_USER
const password = process.env.DEFAULT_PASSWORD
const existingUser = await User.findOne({ username })

if (!existingUser) {
  const hashedPassword = bcrypt.hash(password, 10)
  const newUser = new User({ username, password: hashedPassword })
  await newUser.save()
}

app.use(express.urlencoded({ extended: true }))
app.post('/login', async (req, res) => {
  const { username, password } = req.body

  const user = await User.findOne({ username: username })

  if (user) {
    bcrypt.compare(password, user.password, (err, result) => {
      if (err) {
        console.error(err)
        return res.json({ error: err })
      } else if (result) {
        const token = jwt.sign({ username }, secretKey)

        return res.json({ token })
      } else {
        return res.json({ error: 'Nieprawidłowe hasło!' })
      }
    })
  } else {
    return res.json({ error: 'Nieprawidłowa nazwa użytkownika lub hasło.' })
  }
})
const authenticateToken = (req, res, next) => {
  const token = req.headers.authorization

  if (token) {
    jwt.verify(token, secretKey, (err, decoded) => {
      if (err) {
        return res.sendStatus(403)
      }

      req.user = decoded.username
      next()
    })
  }

  if (!token) {
    return res.sendStatus(401)
  }
}

app.get('/checkConnect', (req, res) => {
  const status = { statusServer: 'Good', statusDB: statusdb }
  res.send(status)
})

app.get('/checkUser', authenticateToken, async (req, res, next) => {
  const users = req.user

  if (users) {
    return res.send(true)
  }
})

app.put('/groups/:id', async (req, res) => {
  const { newName, oldName } = req.body

  const group = await Group.findOneAndUpdate(
    { name: oldName },
    { name: newName }
  )

  if (!group) {
    return res.status(404).json({ error: 'Grupa nie została znaleziona.' })
  }

  return res
    .status(200)
    .json({ message: 'Grupa została zaktualizowana.', group })
})

app.post('/createGroup', async (req, res) => {
  const { name } = req.body
  const existingGroup = await Group.findOne({ name: name })

  if (existingGroup) {
    return res.json({ error: 'Grupa o podanej nazwie już istnieje.' })
  }

  const newGroup = new Group({ name })
  newGroup
    .save()
    .then(() => {
      return res.json({ message: 'Grupa została utworzona pomyślnie.' })
    })
    .catch((error) => {
      console.error(error)
      return res.json({ error: 'Wystąpił błąd podczas tworzenia grupy.' })
    })
})

app.get('/groups', (req, res) => {
  Group.find()
    .then((groups) => {
      const mappedGroups = groups.map((group) => ({
        id: group._id,
        name: group.name,
      }))

      return res.json(mappedGroups)
    })
    .catch((error) => {
      console.error('Error while fetching groups:', error)
      return res.json({ error: 'Wystąpił błąd podczas pobierania grup.' })
    })
})

app.delete('/groups/:id', (req, res) => {
  const { id } = req.params

  Group.findByIdAndDelete(id)
    .then(() => {
      return res.json({ message: 'Grupa została usunięta pomyślnie.' })
    })
    .catch((error) => {
      console.error('Error while deleting group:', error)
      return res.json({ error: 'Wystąpił błąd podczas usuwania grupy.' })
    })
})

app.post('/createContact', async (req, res) => {
  if (!req.body.contact.firstName) {
    return res.json({ error: 'Imię jest wymagane.' })
  }

  if (!req.body.contact.phoneMobile) {
    return res.json({ error: 'Numer telefonu jest wymagany.' })
  }
  const {
    firstName,
    lastName,
    companyName,
    positionInCompany,
    email,
    phoneMobile,
    phoneHome,
    group,
    createNewGroup,
    groupName,
  } = req.body.contact

  const existContact = await Contact.findOne({
    phoneMobile: phoneMobile,
  })

  if (existContact) {
    return res.json({ error: 'Numer telefonu już istnieje.' })
  }

  const getGroupID = await Group.findOne({ name: createNewGroup })

  if (getGroupID) {
    let group = getGroupID.id
    const newContact = new Contact({
      firstName,
      lastName,
      companyName,
      positionInCompany,
      email,
      phoneMobile,
      phoneHome,
      group,
      groupName,
    })

    newContact
      .save()
      .then(() => {
        return res.json({ message: 'Kontakt został utworzony pomyślnie.' })
      })
      .catch((error) => {
        console.error(error)
        return res.json({ error: 'Wystąpił błąd podczas tworzenia kontaktu.' })
      })

    return
  }

  const newContact = new Contact({
    firstName,
    lastName,
    companyName,
    positionInCompany,
    email,
    phoneMobile,
    phoneHome,
    group,
    groupName,
  })

  newContact
    .save()
    .then(() => {
      return res.json({ message: 'Kontakt został utworzony pomyślnie.' })
    })
    .catch((error) => {
      console.error(error)
      return res.json({ error: 'Wystąpił błąd podczas tworzenia kontaktu.' })
    })
})

app.get('/contacts', (req, res) => {
  Contact.find()
    .then((contacts) => {
      const allContact = contacts
        .map((contacts) => ({
          firstName: contacts.firstName,
          lastName: contacts.lastName,
          companyName: contacts.companyName,
          positionInCompany: contacts.positionInCompany,
          email: contacts.email,
          phoneMobile: contacts.phoneMobile,
          phoneHome: contacts.phoneHome,
          group: contacts.group,
          id: contacts._id,
          groupName: contacts.groupName,
        }))
        .filter((contact) => contact.group !== '111111111111')

      return res.json(allContact)
    })
    .catch((error) => {
      console.error('Error while fetching contacts:', error)
      return res.json({ error: 'Wystąpił błąd podczas pobierania kontaktów.' })
    })
})
app.get('/contacts/trash', (req, res) => {
  Contact.find()
    .then((contacts) => {
      const allContact = contacts
        .map((contacts) => ({
          firstName: contacts.firstName,
          lastName: contacts.lastName,
          companyName: contacts.companyName,
          positionInCompany: contacts.positionInCompany,
          email: contacts.email,
          phoneMobile: contacts.phoneMobile,
          phoneHome: contacts.phoneHome,
          group: contacts.group,
          id: contacts._id,
          groupName: contacts.groupName,
        }))
        .filter((contact) => contact.group === '111111111111')

      return res.json(allContact)
    })
    .catch((error) => {
      console.error('Error while fetching contacts:', error)
      return res.json({ error: 'Wystąpił błąd podczas pobierania kontaktów.' })
    })
})
app.put('/contact/delete/:id', async (req, res) => {
  const { newGroup, oldGroup, id } = req.body

  const trash = await Contact.findOneAndUpdate(
    { _id: id, group: oldGroup },
    { group: newGroup },
    { new: true }
  )

  if (!trash) {
    return res
      .status(404)
      .json({ error: 'usunięcie nie powiodło się, nie znaleziono kontaktu' })
  }
  if (trash) {
    return res
      .status(200)
      .json({ message: 'Kontakt została przeniesiony do kosza.', trash })
  }
})
app.post('/preview-contact', (req, res) => {
  const { id } = req.body

  Contact.findOne({ _id: id })
    .then((contact) => {
      return res.json(contact)
    })

    .catch((error) => {
      console.error('Error while fetching groups:', error)
      return res.json({ error: 'Wystąpił błąd podczas pobierania grup.' })
    })
})

app.listen(port, () => {
  console.log(`Server listening on port ${port}.`)
})
