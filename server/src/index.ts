import express from 'express'
import databaseService from '~/services/database.services'
import { defaultErrorHandler } from './middlewares/error.middlewares'
import { config } from 'dotenv'
import mediasRouter from './routes/media.routes'
import usersRouter from './routes/users.routes'
config()

databaseService.connect()
const app = express()
const port = process.env.PORT
app.use(express.json())
app.use('/users', usersRouter)
app.use('/medias', mediasRouter)
app.use(defaultErrorHandler)
app.listen(port, () => {
  console.log(`App listening on http://localhost:${port}`)
})
