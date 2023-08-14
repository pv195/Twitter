import express from 'express'
import databaseService from '~/services/database.services'
import userRouter from './routes/users.routes'
import { defaultErrorHandler } from './middlewares/error.middlewares'
import { config } from 'dotenv'
config()

databaseService.connect()
const app = express()
const port = process.env.PORT
app.use(express.json())
app.use('/users', userRouter)
app.use(defaultErrorHandler)
app.listen(port, () => {
  console.log(`App listening on http://localhost:${port}`)
})
