import User from '~/models/schemas/User.schema'
import databaseService from './database.services'
import { RegisterReqBody, UpdateMyProfileReqBody } from '~/models/requests/User.requests'
import { hashPassword } from '~/utils/crypto'
import { signToken } from '~/utils/jwt'
import { TokenType, UserVerifyStatus } from '~/constants/enums'
import RefreshToken from '~/models/schemas/RefreshToken.schema'
import { ObjectId } from 'mongodb'
import axios from 'axios'
import { config } from 'dotenv'
import { USERS_MESSAGES } from '~/constants/messages'
import { ErrorWithStatus } from '~/models/Error'
import HTTP_STATUS from '~/constants/httpStatus'
import Follower from '~/models/schemas/Follower.schema'
config()

class UsersService {
  private signAccessToken({ user_id, verify }: { user_id: string; verify: UserVerifyStatus }) {
    return signToken({
      payload: {
        user_id,
        token_type: TokenType.AccessToken,
        verify
      },
      options: {
        expiresIn: process.env.ACCESSTOKEN_EXPIRES_IN as string
      }
    })
  }

  private signRefreshToken({ user_id, verify }: { user_id: string; verify: UserVerifyStatus }) {
    return signToken({
      payload: {
        user_id,
        token_type: TokenType.EmailVerifyToken,
        verify
      },
      privateKey: process.env.EMAIL_VERIFY_SECRET_KEY as string,
      options: {
        expiresIn: process.env.EMAIL_VERIFY_EXPIRES_IN as string
      }
    })
  }

  private signEmailVerifyToken(user_id: string) {
    return signToken({
      payload: {
        user_id,
        token_type: TokenType.RefreshToken
      },
      privateKey: process.env.EMAIL_VERIFY_SECRET_KEY as string,
      options: {
        expiresIn: process.env.ACCESSTOKEN_EXPIRES_IN as string
      }
    })
  }

  private signForgotPasswordToken(user_id: string) {
    return signToken({
      payload: {
        user_id,
        token_type: TokenType.ForgotPasswordToken
      },
      privateKey: process.env.FORGOT_PASSWORD_SECRET_KEY as string,
      options: {
        expiresIn: process.env.FORGOT_PASSWORD_EXPIRES_IN as string
      }
    })
  }

  private signAccessTokenAndRefreshToken({ user_id, verify }: { user_id: string; verify: UserVerifyStatus }) {
    return Promise.all([this.signAccessToken({ user_id, verify }), this.signRefreshToken({ user_id, verify })])
  }

  async register(payload: RegisterReqBody) {
    const user_id = new ObjectId()
    const email_verify_token = await this.signEmailVerifyToken(user_id.toString())
    //Send email
    console.log('email_verify_token', email_verify_token)
    await databaseService.users.insertOne(
      new User({
        ...payload,
        _id: user_id,
        username: `user${user_id.toString()}`,
        email_verify_token,
        date_of_birth: new Date(payload.date_of_birth),
        password: hashPassword(payload.password)
      })
    )

    const [access_token, refresh_token] = await this.signAccessTokenAndRefreshToken({
      user_id: user_id.toString(),
      verify: UserVerifyStatus.Unverified
    })
    await databaseService.refreshToken.insertOne(
      new RefreshToken({ user_id: new ObjectId(user_id), token: refresh_token })
    )

    return {
      access_token,
      refresh_token
    }
  }

  private async getOAuthGoogleToken(code: string) {
    const body = {
      code,
      client_id: process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      redirect_uri: process.env.GOOGLE_REDIRECT_URI,
      grant_type: 'authorization_code'
    }
    const { data } = await axios.post('https://oauth2.googleapis.com/token', body, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    })

    return data as {
      access_token: string
      id_token: string
    }
  }

  private async getGoogleUserInfo(access_token: string, id_token: string) {
    const { data } = await axios.get('https://www.googleapis.com/oauth2/v1/userinfo', {
      params: {
        access_token,
        alt: 'json'
      },
      headers: {
        Authorization: `Bearer ${id_token}`
      }
    })
    console.log(data)
    return data as {
      id: string
      email: string
      verified_email: boolean
      name: string
      given_name: string
      family_name: string
      picture: string
      locale: string
    }
  }

  async oAuth(code: string) {
    const { id_token, access_token } = await this.getOAuthGoogleToken(code)
    const userInfo = await this.getGoogleUserInfo(access_token, id_token)
    if (!userInfo.verified_email) {
      throw new ErrorWithStatus({
        message: USERS_MESSAGES.GMAIL_NOT_VERIFIED,
        status: HTTP_STATUS.BAD_REQUEST
      })
    }

    const user = await databaseService.users.findOne({ email: userInfo.email })
    if (user) {
      const [access_token, refresh_token] = await this.signAccessTokenAndRefreshToken({
        user_id: user._id.toString(),
        verify: UserVerifyStatus.Verified
      })
      await databaseService.refreshToken.insertOne(new RefreshToken({ user_id: user._id, token: refresh_token }))

      return {
        access_token,
        refresh_token,
        newUser: 0,
        verify: user.verify
      }
    } else {
      const randomstring = Math.random().toString(36).slice(-12)
      const data = await this.register({
        email: userInfo.email,
        name: userInfo.name,
        date_of_birth: new Date().toISOString(),
        password: randomstring,
        confirm_password: randomstring
      })
      return { ...data, newUser: 1, verify: UserVerifyStatus.Unverified }
    }
  }

  async login({ user_id, verify }: { user_id: string; verify: UserVerifyStatus }) {
    const [access_token, refresh_token] = await this.signAccessTokenAndRefreshToken({ user_id, verify })
    await databaseService.refreshToken.insertOne(
      new RefreshToken({ user_id: new ObjectId(user_id), token: refresh_token })
    )

    await databaseService.refreshToken.insertOne(
      new RefreshToken({ user_id: new ObjectId(user_id), token: refresh_token })
    )

    return {
      access_token,
      refresh_token
    }
  }

  async checkEmailExist(email: string) {
    const user = await databaseService.users.findOne({ email })

    return Boolean(user)
  }

  async logout(refresh_token: string) {
    await databaseService.refreshToken.deleteOne({ token: refresh_token })

    return {
      message: USERS_MESSAGES.LOGOUT_SUCCESS
    }
  }

  async refreshToken({
    user_id,
    refresh_token,
    verify
  }: {
    user_id: string
    refresh_token: string
    verify: UserVerifyStatus
  }) {
    const [new_tokens] = await Promise.all([
      this.signAccessTokenAndRefreshToken({ user_id, verify }),
      databaseService.refreshToken.deleteOne({ token: refresh_token })
    ])
    const [new_access_token, new_refresh_Token] = new_tokens
    await databaseService.refreshToken.insertOne(
      new RefreshToken({ user_id: new ObjectId(user_id), token: new_refresh_Token })
    )

    return {
      accessToken: new_access_token,
      refresh_Token: new_refresh_Token
    }
  }

  async verifyEmail(user_id: string) {
    const [tokens] = await Promise.all([
      this.signAccessTokenAndRefreshToken({
        user_id: user_id.toString(),
        verify: UserVerifyStatus.Verified
      }),
      databaseService.users.updateOne(
        {
          _id: new ObjectId(user_id)
        },
        [
          {
            $set: {
              email_verify_token: '',
              verify: UserVerifyStatus.Verified,
              updated_at: '$$NOW'
            }
          }
        ]
      )
    ])
    const [access_token, refresh_token] = tokens

    return {
      access_token,
      refresh_token
    }
  }

  async resendVerifyEmail(user_id: string) {
    const email_verify_token = await this.signEmailVerifyToken(user_id)
    console.log('Resend verify email', email_verify_token)

    databaseService.users.updateOne(
      {
        _id: new ObjectId(user_id)
      },
      {
        $set: {
          email_verify_token
        },
        $currentDate: {
          updated_at: true
        }
      }
    )

    return {
      message: USERS_MESSAGES.RESEND_VERIFY_EMAIL_SUCCESS
    }
  }

  async forgotPassword(user_id: string) {
    const forgot_password_token = await this.signForgotPasswordToken(user_id)
    await databaseService.users.updateOne(
      {
        _id: new ObjectId(user_id)
      },
      {
        $set: {
          forgot_password_token
        },
        $currentDate: {
          updated_at: true
        }
      }
    )

    //Send mail that has a link to reset password: http://twitter.com/forgot-password?token=token
    console.log('forgot_password_token', forgot_password_token)

    return {
      message: USERS_MESSAGES.CHECK_EMAIL_TO_RESET_PASSWORD
    }
  }

  async resetPassword(user_id: string, password: string) {
    await databaseService.users.updateOne(
      {
        _id: new ObjectId(user_id)
      },
      {
        $set: {
          forgot_password_token: '',
          password: hashPassword(password)
        },
        $currentDate: {
          updated_at: true
        }
      }
    )

    return {
      message: USERS_MESSAGES.RESET_PASSWORD_SUCCESS
    }
  }

  async getMyProfile(user_id: string) {
    const user = await databaseService.users.findOne(
      { _id: new ObjectId(user_id) },
      {
        projection: {
          created_at: 0,
          updated_at: 0,
          password: 0,
          email_verify_token: 0,
          forgot_password_token: 0,
          verify: 0,
          bio: 0
        }
      }
    )

    return user
  }

  async updateMyProfile(user_id: string, payload: UpdateMyProfileReqBody) {
    const _payload = payload.date_of_birth ? { ...payload, date_of_birth: new Date(payload.date_of_birth) } : payload
    const updatedProfile = await databaseService.users.findOneAndUpdate(
      {
        _id: new ObjectId(user_id)
      },
      {
        $set: {
          ...(_payload as UpdateMyProfileReqBody & { date_of_birth?: Date })
        },
        $currentDate: {
          updated_at: true
        }
      },
      {
        returnDocument: 'after',
        projection: {
          created_at: 0,
          updated_at: 0,
          password: 0,
          email_verify_token: 0,
          forgot_password_token: 0,
          verify: 0,
          bio: 0
        }
      }
    )

    return updatedProfile.value
  }

  async getUserProfile(username: string) {
    const user = await databaseService.users.findOne(
      { username },
      {
        projection: {
          created_at: 0,
          updated_at: 0,
          password: 0,
          email_verify_token: 0,
          forgot_password_token: 0,
          verify: 0,
          bio: 0
        }
      }
    )
    if (user === null) {
      throw new ErrorWithStatus({
        message: USERS_MESSAGES.USER_NOT_FOUND,
        status: HTTP_STATUS.NOT_FOUND
      })
    }

    return user
  }

  async follow(user_id: string, followed_user_id: string) {
    const follower = await databaseService.followers.findOne({
      user_id: new ObjectId(user_id),
      followed_user_id: new ObjectId(followed_user_id)
    })
    if (follower !== null) {
      return {
        messsage: USERS_MESSAGES.FOLLOWED_USER
      }
    }

    await databaseService.followers.insertOne(
      new Follower({
        user_id: new ObjectId(user_id),
        followed_user_id: new ObjectId(followed_user_id)
      })
    )

    return {
      messsage: USERS_MESSAGES.FOLLOW_SUCCESS
    }
  }

  async unfollow(user_id: string, followed_user_id: string) {
    const follower = await databaseService.followers.findOne({ user_id: new ObjectId(user_id) })

    if (follower === null) {
      return {
        messsage: USERS_MESSAGES.ALREADY_UNFOLLOW
      }
    }

    await databaseService.followers.deleteOne({
      user_id: new ObjectId(user_id),
      followed_user_id: new ObjectId(followed_user_id)
    })

    return {
      messsage: USERS_MESSAGES.UNFOLLOW_SUCCESS
    }
  }

  async changePassword(user_id: string, new_password: string) {
    await databaseService.users.findOneAndUpdate(
      { id: new ObjectId(user_id) },
      {
        $set: {
          password: hashPassword(new_password)
        },
        $currentDate: {
          updated_at: true
        }
      }
    )
    return {
      message: USERS_MESSAGES.CHANGE_PASSWORD_SUCCESS
    }
  }
}

const usersService = new UsersService()
export default usersService
