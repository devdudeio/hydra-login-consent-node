import express from 'express'
import url from 'url'
import urljoin from 'url-join'
import csrf from 'csurf'
import {hydraAdmin, verusClient} from '../config'
import {oidcConformityMaybeFakeAcr} from './stub/oidc-cert'
import {WALLET_VDXF_KEY, LOGIN_CONSENT_REQUEST_VDXF_KEY, LOGIN_CONSENT_REQUEST_SIG_VDXF_KEY, LOGIN_CONSENT_CLIENT_VDXF_KEY, LOGIN_CONSENT_REDIRECT_VDXF_KEY, LOGIN_CONSENT_CHALLENGE_VDXF_KEY, LoginConsentResponse, VerusIDSignature, LoginConsentDecision, LoginConsentRequest, LOGIN_CONSENT_RESPONSE_VDXF_KEY} from 'verus-typescript-primitives';
import base64url from 'base64url'
import { Challenge, ChallengeInterface } from 'verus-typescript-primitives/dist/vdxf/classes/Challenge'
import { Client } from 'verus-typescript-primitives/dist/vdxf/classes/Client'
const util = require('util')


// Sets up csrf protection
const csrfProtection = csrf({cookie: true})
const router = express.Router()

router.get('/', csrfProtection, async (req, res, next) => {


    const loginConsentResponse = new LoginConsentResponse(JSON.parse(base64url.decode(String(req.query[LOGIN_CONSENT_RESPONSE_VDXF_KEY.vdxfid]))));
    const challenge = loginConsentResponse.decision.request.challenge.uuid;
    const isValid = await verusClient['vrsctest'].post('', {
      method: 'verifymessage',
      params: [
          loginConsentResponse.signing_id,
          loginConsentResponse.signature?.signature,
          loginConsentResponse.getSignedData()
      ]})
    .then(res => res.data.result)
    .catch(() => false);

    // Let's see if the user decided to accept or reject the consent request..
    if (!isValid) {
        // Looks like the consent request was denied by the user
        return (
            hydraAdmin
                .rejectLoginRequest(challenge, {
                    error: 'access_denied',
                    error_description: 'not valid'
                })
                .then(({data: body}) => {
                    // All we need to do now is to redirect the browser back to hydra!
                    res.redirect(String(body.redirect_to))
                })
                // This will handle any error that happens when making HTTP calls to hydra
                .catch(next)
        )
    }

    // Seems like the user authenticated! Let's tell hydra...

    hydraAdmin
        .getLoginRequest(challenge)
        .then(({data: loginRequest}) =>
            hydraAdmin
                .acceptLoginRequest(challenge, {
                    // Subject is an alias for user ID. A subject can be a random string, a UUID, an email address, ....
                    subject: loginConsentResponse.signing_id,

                    // This tells hydra to remember the browser and automatically authenticate the user in future requests. This will
                    // set the "skip" parameter in the other route to true on subsequent requests!
                    remember: Boolean(loginConsentResponse.decision.remember),

                    // When the session expires, in seconds. Set this to 0 so it will never expire.
                    remember_for: loginConsentResponse?.decision?.remember_for || 3600,

                    // Sets which "level" (e.g. 2-factor authentication) of authentication the user has. The value is really arbitrary
                    // and optional. In the context of OpenID Connect, a value of 0 indicates the lowest authorization level.
                    // acr: '0',
                    //
                    // If the environment variable CONFORMITY_FAKE_CLAIMS is set we are assuming that
                    // the app is built for the automated OpenID Connect Conformity Test Suite. You
                    // can peak inside the code for some ideas, but be aware that all data is fake
                    // and this only exists to fake a login system which works in accordance to OpenID Connect.
                    //
                    // If that variable is not set, the ACR value will be set to the default passed here ('0')
                    acr: oidcConformityMaybeFakeAcr(loginRequest, '0')
                })
                .then(({data: body}) => {
                    // All we need to do now is to redirect the user back to hydra!
                    res.redirect(String(body.redirect_to))
                })
        )
        // This will handle any error that happens when making HTTP calls to hydra
        .catch(next)

    // You could also deny the login request which tells hydra that no one authenticated!
    // hydra.rejectLoginRequest(challenge, {
    //   error: 'invalid_request',
    //   errorDescription: 'The user did something stupid...'
    // })
    //   .then(({body}) => {
    //     // All we need to do now is to redirect the browser back to hydra!
    //     res.redirect(String(body.redirectTo));
    //   })
    //   // This will handle any error that happens when making HTTP calls to hydra
    //   .catch(next);
})

export default router


