import { Request } from 'express'
import path from 'path'
import sharp from 'sharp'
import { UPLOAD_IMAGE_DIR } from '~/constants/dir'
import { getNameFromFullName, handleUploadImage, handleUploadVideo } from '~/utils/file'
import fs from 'fs'
import { isProduction } from '~/constants/config'
import { config } from 'dotenv'
import { MediaType } from '~/constants/enums'
import { Media } from '~/models/Other'
import { encodeHLSWithMultipleVideoStreams } from '~/utils/video'
config()

class MediaService {
  async handleUploadImage(req: Request) {
    const files = await handleUploadImage(req)
    const result: Media[] = await Promise.all(
      files.map(async (file) => {
        const newName = getNameFromFullName(file.newFilename)
        const newPath = path.resolve(UPLOAD_IMAGE_DIR, `${newName}.jpg`)
        await sharp(file.filepath).jpeg().toFile(newPath)
        fs.unlinkSync(file.filepath) //  remove image in temp folder
        return {
          url: isProduction
            ? `${process.env.HOST}/static/image/${newName}.jpg`
            : `http://localhost:${process.env.PORT}/static/image/${newName}.jpg`,
          type: MediaType.Image
        }
      })
    )
    return result
  }

  async handleUploadVideo(req: Request) {
    const files = await handleUploadVideo(req)
    const { newFilename } = files[0]
    return {
      url: isProduction
        ? `${process.env.HOST}/static/video/${newFilename}`
        : `http://localhost:${process.env.PORT}/static/video/${newFilename}`,
      type: MediaType.Video
    }
    // const result: Media[] = await Promise.all(
    //   files.map(async (file) => {
    //     const newName = getNameFromFullName(file.newFilename)
    //     const newPath = path.resolve(UPLOAD_IMAGE_DIR, `${newName}.jpg`)
    //     await sharp(file.filepath).jpeg().toFile(newPath)
    //     fs.unlinkSync(file.filepath) //  remove image in temp folder
    //     return {
    //       url: isProduction
    //         ? `${process.env.HOST}/static/video/${newName}.jpg`
    //         : `http://localhost:${process.env.PORT}/static/video/${newName}.jpg`,
    //       type: MediaType.Video
    //     }
    //   })
    // )
    // return result
  }

  async handleUploadVideoHLS(req: Request) {
    const files = await handleUploadVideo(req)
    const { newFilename, filepath } = files[0]
    await encodeHLSWithMultipleVideoStreams(filepath)
    return {
      url: isProduction
        ? `${process.env.HOST}/static/video/${newFilename}`
        : `http://localhost:${process.env.PORT}/static/video/${newFilename}`,
      type: MediaType.Video
    }
    // const result: Media[] = await Promise.all(
    //   files.map(async (file) => {
    //   await encodeHLSWithMultipleVideoStreams(filepath)
    //     return {
    //       url: isProduction
    //         ? `${process.env.HOST}/static/video/${newName}.jpg`
    //         : `http://localhost:${process.env.PORT}/static/video/${newName}.jpg`,
    //       type: MediaType.Video
    //     }
    //   })
    // )
  }
}

const mediasService = new MediaService()
export default mediasService
