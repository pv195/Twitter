import express from 'express'
import databaseService from '~/services/database.services'
import { defaultErrorHandler } from './middlewares/error.middlewares'
import { config } from 'dotenv'
import mediasRouter from './routes/media.routes'
import usersRouter from './routes/users.routes'
import { initFolder } from './utils/file'
import { UPLOAD_IMAGE_DIR, UPLOAD_VIDEO_DIR } from './constants/dir'
import staticRouter from './routes/static.routes'

config()

databaseService.connect()
const app = express()
const port = process.env.PORT || 4000

initFolder()

app.use(express.json())
app.use('/users', usersRouter)
app.use('/medias', mediasRouter)
app.use('/static', staticRouter) // dễ customize lỗi và middleware
// app.use('/static/video', express.static(UPLOAD_VIDEO_DIR)) // khó customize

app.use(defaultErrorHandler)
app.listen(port, () => {
  console.log(`App listening on http://localhost:${port}`)
})
