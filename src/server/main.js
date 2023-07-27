import * as dotenv from 'dotenv'
import express from 'express'
import cors from 'cors'
import mongoose from 'mongoose'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'

dotenv.config()
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
  isContacts: {
    type: Number,
    default: 0,
  },
})
const contactSchema = new mongoose.Schema({
  firstName: {
    type: String,
    require: true,
  },
  lastName: String,
  companyName: String,
  positionInCompany: String,
  email: String,
  phoneMobile: {
    type: String,
    require: true,
  },
  phoneHome: String,
  group: {
    type: String,
    ref: 'groups',
  },
  groupName: String,
})

const contactSchemaDelete = new mongoose.Schema({
  id: {
    type: String,
    require: true,
  },
  dataDeleted: String,
})

const Group = mongoose.model('groups', groupSchema)
const Contact = mongoose.model('contacts', contactSchema)
const DeleteContacts = mongoose.model('DeleteContacts', contactSchemaDelete)

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
        isContacts: group.isContacts,
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
  const { withContacts } = req.query

  if (!withContacts) {
    Group.findByIdAndDelete(id)
      .then(() => {
        return Contact.updateMany(
          { group: id },
          { group: '000000000000', groupName: 'Kontakty' }
        )
      })
      .then(() => {
        return res.json({ message: 'Grupa została usunięta pomyślnie.' })
      })
      .catch((error) => {
        console.error('Error while deleting group:', error)
        return res.json({ error: 'Wystąpił błąd podczas usuwania grupy.' })
      })
  }

  if (withContacts) {
    Promise.all([
      Group.findByIdAndDelete(id),
      Contact.deleteMany({ group: id }),
    ])
      .then(() => {
        return res.json({
          message: 'Grupa i kontakty zostały usunięte pomyślnie.',
        })
      })
      .catch((error) => {
        console.error('Error while deleting group and contacts:', error)
        return res.json({
          error: 'Wystąpił błąd podczas usuwania grupy i kontaktów.',
        })
      })
  }
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

app.post('/createContact/import', async (req, res) => {
  const contacts = req.body.contact

  try {
    await Promise.all(
      contacts.map(async (contact) => {
        const {
          firstName,
          lastName,
          companyName,
          positionInCompany,
          email,
          phoneMobile,
          phoneHome,
          group,
          groupName,
        } = contact

        const existingContact = await Contact.findOne({
          firstName,
          lastName,
          email,
          phoneMobile,
        })

        if (!existingContact) {
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

          await newContact.save()
        } else {
          // console.log('Kontakt już istnieje:', existingContact)
        }
      })
    )

    return res.json({ message: 'Import zakończony' })
  } catch (error) {
    console.error('Błąd podczas tworzenia kontaktu:', error)
    return res
      .status(500)
      .json({ error: 'Wystąpił błąd podczas importowania kontaktów' })
  }
})

app.get('/contacts', (req, res) => {
  Group.find().then((groups) => {
    const groupIds = groups.map((group) => group._id)

    Contact.find({ group: { $in: groupIds } }).then((contacts) => {
      const contactCountMap = {}

      contacts.forEach((contact) => {
        if (!contactCountMap[contact.group]) {
          contactCountMap[contact.group] = 0
        }
        contactCountMap[contact.group]++
      })

      const updatedGroups = groups.map((group) => ({
        id: group._id,
        name: group.name,
        isContacts: contactCountMap[group._id] || 0,
      }))
      const savePromises = updatedGroups.map((updatedGroup) => {
        return Group.findByIdAndUpdate(
          updatedGroup.id,
          { isContacts: updatedGroup.isContacts },
          { new: true }
        )
      })

      Promise.all(savePromises)
    })
  })

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

  const currentDate = new Date()
  const year = currentDate.getFullYear()
  const month = (currentDate.getMonth() + 1).toString().padStart(2, '0')
  const day = currentDate.getDate().toString().padStart(2, '0')

  const trash = await Contact.findOneAndUpdate(
    { _id: id, group: oldGroup },
    { group: newGroup, groupName: 'Kosz' },
    { new: true }
  )
  const existContact = await DeleteContacts.findOne({
    id: id,
  })

  if (!existContact) {
    const deleteContacts = new DeleteContacts({
      id: id,
      dataDeleted: `${year}-${month}-${day}`,
    })

    deleteContacts.save()
  }

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
app.put('/contact/deleteMany/', async (req, res) => {
  const { newGroup, checkedContacts } = req.body

  const allContacts = checkedContacts.map((value) => {
    return value.id
  })

  try {
    await Contact.updateMany(
      { _id: allContacts }, // Empty filter to update all contacts
      {
        $set: {
          group: newGroup,
          groupName: 'Kosz',
        },
      }
    )
    return res.status(200).json({
      message: 'Kontakty zostały przeniesione do kosza.',
    })
  } catch (error) {
    return res.status(500).json({
      error: 'Wystąpił błąd podczas usuwania kontaktów',
    })
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
      return res.json({ error: 'Wystąpił błąd podczas pobierania kontaktu.' })
    })
})
app.put('/contact/edit/group/', async (req, res) => {
  const newGroup = req.body.newGroup

  const newG = await Group.findOne({ name: newGroup })

  const allContacts = req.body.contacts.map((value) => {
    return value.id
  })

  if (!newG) {
    if (newGroup === 'Wolne Numery') {
      try {
        await Contact.updateMany(
          { _id: allContacts }, // Empty filter to update all contacts
          {
            $set: {
              group: '222222222222',
              groupName: 'Wolne Numery',
            },
          }
        )

        return res.status(200).json({
          message: 'Kontakty zostały przypisane do nowej grupy',
        })
      } catch (error) {
        return res.status(500).json({
          error: 'Wystąpił błąd podczas aktualizacji grupy kontaktów.',
        })
      }
    }
    return
  }

  try {
    await Contact.updateMany(
      { _id: allContacts }, // Empty filter to update all contacts
      {
        $set: {
          group: newG._id,
          groupName: newG.name,
        },
      }
    )

    return res.status(200).json({
      message: 'Kontakty zostały przypisane do nowej grupy',
    })
  } catch (error) {
    return res
      .status(500)
      .json({ error: 'Wystąpił błąd podczas aktualizacji grupy kontaktów.' })
  }
})
app.put('/contact/edit/:id', async (req, res) => {
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

  const contactId = req.params.id

  const getGroupID = await Group.findOne({ name: createNewGroup })

  if (getGroupID) {
    let group = getGroupID.id

    const updatedContact = await Contact.findOneAndUpdate(
      { _id: contactId },
      {
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
      },
      { new: true }
    )

    if (!updatedContact) {
      return res.status(404).json({ error: 'Kontakt nie została znaleziona.' })
    }

    return res
      .status(200)
      .json({ message: 'Kontakt została zaktualizowany.', updatedContact })
  }

  const updatedContact = await Contact.findOneAndUpdate(
    { _id: contactId },
    {
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
    },
    { new: true }
  )

  const deleteFromTrash = await DeleteContacts.findOneAndDelete({
    id: contactId,
  })

  if (!updatedContact || !deleteFromTrash) {
    return res.status(404).json({ error: 'Kontakt nie został zaktualizowany.' })
  }

  return res
    .status(200)
    .json({ message: 'Kontakt została zaktualizowany.', updatedContact })
})
app.get('/contacts/free-numbers', (req, res) => {
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
        .filter((contact) => contact.group === '222222222222')

      return res.json(allContact)
    })
    .catch((error) => {
      console.error('Error while fetching contacts:', error)
      return res.json({ error: 'Wystąpił błąd podczas pobierania kontaktów.' })
    })
})
app.get('/contacts/groups', (req, res) => {
  const { selectedGroup } = req.query

  Group.findOne({ name: selectedGroup }).then((group) => {
    if (!group) {
      return
    }
    const idGroup = group._id.toString()

    Contact.find({ group: idGroup })
      .then((contacts) => {
        const allContact = contacts
          .map((contact) => ({
            firstName: contact.firstName,
            lastName: contact.lastName,
            companyName: contact.companyName,
            positionInCompany: contact.positionInCompany,
            email: contact.email,
            phoneMobile: contact.phoneMobile,
            phoneHome: contact.phoneHome,
            group: contact.group,
            id: contact._id,
            groupName: contact.groupName,
          }))
          .filter((contact) => contact.group === idGroup)

        return res.json(allContact)
      })
      .catch((error) => {
        console.error('Error while fetching contacts:', error)
        return res.status(500).json({
          error: 'Wystąpił błąd podczas pobierania kontaktów.',
        })
      })
  })
})

app.put('/checkContactsInTrash', (req, res) => {
  const currentDate = new Date()
  const thirtyDaysInMilliseconds = 30 * 24 * 60 * 60 * 1000

  DeleteContacts.find().then((contacts) => {
    contacts.forEach((contact) => {
      const data = new Date(contact.dataDeleted)
      const differenceInTime = data.getTime() - currentDate.getTime()

      if (differenceInTime > thirtyDaysInMilliseconds) {
        Contact.findByIdAndDelete(contact.id)
        DeleteContacts.findOneAndDelete({ id: contact.id })
          .then(() => {
            console.log(`Kontakt o ID ${contact.id} został usunięty.`)
          })
          .catch((error) => {
            console.error(
              `Wystąpił błąd podczas usuwania kontaktu o ID ${contact.id}:`,
              error
            )
          })
      }
    })
  })
})

app.listen(port, () => {
  console.log(`Server listening on port ${port}.`)
})
