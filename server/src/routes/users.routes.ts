import { Router } from 'express'
import {
  changePasswordController,
  followController,
  forgotPasswordController,
  getMyProfileController,
  getUserProfileController,
  loginController,
  logoutController,
  oAuthControllers,
  refreshTokenController,
  registerController,
  resendEmailVerifyController,
  resetPasswordController,
  unfollowController,
  updateMyProfileController,
  verifyEmailController,
  verifyForgotPasswordController
} from '~/controllers/users.controllers'
import { filterMiddleware } from '~/middlewares/common.middlewares'
import {
  accessTokenValidator,
  changePasswordValidator,
  emailForgotPasswordValidator,
  emailVerifyTokenValidator,
  followValidator,
  forgotPasswordTokenValidator,
  loginValidator,
  refreshTokenValidator,
  registerValidator,
  resetPasswordValidator,
  unfollowValidator,
  updateMyProfileValidator,
  verifiedUserValidator
} from '~/middlewares/users.middlewares'
import { UpdateMyProfileReqBody } from '~/models/requests/User.requests'
import { warpRequestHandler } from '~/utils/handlers'
const usersRouter = Router()

/**
 * Description: Login a user
 * Path: /login
 * Method: POST
 * Body: { email: string, password: string }
 */
usersRouter.post('/login', loginValidator, warpRequestHandler(loginController))

/**
 * Description: Login with google account
 * Path: /oauth/google
 * Method: GET
 */
usersRouter.get('/oauth/google', warpRequestHandler(oAuthControllers))

/**
 * Description: Register a new user
 * Path: /register
 * Method: POST
 * Body: { name: string, email: string, password: string, confirm_password: string, date_of_birth: ISO8601 }
 */
usersRouter.post('/register', registerValidator, warpRequestHandler(registerController))

/**
 * Description: Logout a user
 * Path: /logout
 * Method: POST
 * Header: { Authorization: Bear <access_token> }
 * Body: { refresh_token: string }
 */
usersRouter.post('/logout', accessTokenValidator, refreshTokenValidator, warpRequestHandler(logoutController))

/**
 * Description: Refresh token
 * Path: /refresh-token
 * Method: POST
 * Body: { refresh_token: string }
 */
usersRouter.post('/refresh-token', refreshTokenValidator, warpRequestHandler(refreshTokenController))

/**
 * Description: Verify email when user client click on the link in email
 * Path: /verify-email
 * Method: POST
 * Body: { email_verify_token: string }
 */
usersRouter.post('/verify-email', emailVerifyTokenValidator, warpRequestHandler(verifyEmailController))

/**
 * Description: Resend verify email when user client click resend email
 * Path: /resend-verify-email
 * Method: POST
 * Header: { Authorization: Bear <access_token> }
 */
usersRouter.post('/resend-verify-email', accessTokenValidator, warpRequestHandler(resendEmailVerifyController))

/**
 * Description: Submit email to request to reset password, send email to user
 * Path: /forgot-password
 * Method: POST
 * Body: { email: string }
 */
usersRouter.post('/forgot-password', emailForgotPasswordValidator, warpRequestHandler(forgotPasswordController))

/**
 * Description: Verify forgot password token in email
 * Path: /verify-forgot-password
 * Method: POST
 * Body: { forgot_password_token: string }
 */
usersRouter.post(
  '/verify-forgot-password',
  forgotPasswordTokenValidator,
  warpRequestHandler(verifyForgotPasswordController)
)

/**
 * Description: Reset password
 * Path: /reset-password
 * Method: POST
 * Body: { forgot_password_token: string, password: string, confirm_password: string }
 */
usersRouter.post('/reset-password', resetPasswordValidator, warpRequestHandler(resetPasswordController))

/**
 * Description: Get my profile
 * Path: /me
 * Method: GET
 * Header: { Authorization: Bear <access_token> }
 */
usersRouter.get('/me', accessTokenValidator, warpRequestHandler(getMyProfileController))

/**
 * Description: Get user profile
 * Path: /:username
 * Method: GET
 */
usersRouter.get('/:username', warpRequestHandler(getUserProfileController))

/**
 * Description: Update my profile
 * Path: /me
 * Method: PATCH
 * Header: { Authorization: Bear <access_token> }
 * Body: UserSchema: ['name', 'date_of_birth', 'bio', 'location', 'website', 'username', 'avatar', 'cover_photo']
 */
usersRouter.patch(
  '/me',
  accessTokenValidator,
  verifiedUserValidator,
  updateMyProfileValidator,
  filterMiddleware<UpdateMyProfileReqBody>([
    'name',
    'date_of_birth',
    'bio',
    'location',
    'website',
    'username',
    'avatar',
    'cover_photo'
  ]),
  warpRequestHandler(updateMyProfileController)
)

/**
 * Description: Follow user
 * Path: /follow
 * Method: POST
 * Header: { Authorization: Bear <access_token> }
 * Body: { followed_user_id: string }
 */
usersRouter.post(
  '/follow',
  accessTokenValidator,
  verifiedUserValidator,
  followValidator,
  warpRequestHandler(followController)
)

/**
 * Description: Unfollow user
 * Path: /follow/:user_id
 * Method: Delete
 * Header: { Authorization: Bear <access_token> }
 */
usersRouter.delete(
  '/follow/:user_id',
  accessTokenValidator,
  verifiedUserValidator,
  unfollowValidator,
  warpRequestHandler(unfollowController)
)

usersRouter.put(
  '/change-password',
  accessTokenValidator,
  verifiedUserValidator,
  changePasswordValidator,
  warpRequestHandler(changePasswordController)
)

export default usersRouter
