import express from 'express'
import url from 'url'
import urljoin from 'url-join'
import csrf from 'csurf'
import {hydraAdmin, verusClient} from '../config'
import {oidcConformityMaybeFakeAcr} from './stub/oidc-cert'
import {WALLET_VDXF_KEY, LOGIN_CONSENT_REQUEST_VDXF_KEY, LOGIN_CONSENT_REQUEST_SIG_VDXF_KEY, LOGIN_CONSENT_CLIENT_VDXF_KEY, LOGIN_CONSENT_REDIRECT_VDXF_KEY, LOGIN_CONSENT_CHALLENGE_VDXF_KEY, LoginConsentResponse, VerusIDSignature, LoginConsentDecision, LoginConsentRequest} from 'verus-typescript-primitives';
import base64url from 'base64url'
import { Challenge, ChallengeInterface } from 'verus-typescript-primitives/dist/vdxf/classes/Challenge'
import { Client } from 'verus-typescript-primitives/dist/vdxf/classes/Client'
const util = require('util')


// Sets up csrf protection
const csrfProtection = csrf({cookie: true})
const router = express.Router()

router.get('/', csrfProtection, (req, res, next) => {
    // Parses the URL query
    const query = url.parse(req.url, true).query

    // The challenge is used to fetch information about the login request from ORY Hydra.
    const challenge = String(query.login_challenge)
    if (!challenge) {
        next(new Error('Expected a login challenge to be set but received none.'))
        return
    }

    hydraAdmin
        .getLoginRequest(challenge)
        .then(async ({data: body}) => {
            // If hydra was already able to authenticate the user, skip will be true and we do not need to re-authenticate
            // the user.
            if (body.skip) {
                // You can apply logic here, for example update the number of times the user logged in.
                // ...

                // Now it's time to grant the login request. You could also deny the request if something went terribly wrong
                // (e.g. your arch-enemy logging in...)
                return hydraAdmin
                    .acceptLoginRequest(challenge, {
                        // All we need to do is to confirm that we indeed want to log in the user.
                        subject: String(body.subject)
                    })
                    .then(({data: body}) => {
                        // All we need to do now is to redirect the user back to hydra!
                        res.redirect(String(body.redirect_to))
                    })
            }

            // If authentication can't be skipped we MUST show the login UI.
            // Here it should redirect to open veruswallet

            const challengeClient = new Client({
                client_id: body.client.client_id || '',
                name: body.client.client_name || 'Fancy Client Name',
                //@ts-ignore
                redirect_uris: ["http://127.0.0.1:3000/verifyLogin?"].map(uri => ({type: LOGIN_CONSENT_REDIRECT_VDXF_KEY.vdxfid, uri})),
                grant_types: body.client.grant_types,
                response_types: body.client.response_types,
                scope: 'i7TBEho8TUPg4ESPmGRiiDMGF55QJM37Xk', //body.client.scope, // TODO: this should be coming from the client app login link but will be overrritten here for testing 
                audience: body.client.audience || null,
                owner: body.client.owner,
                policy_uri: body.client.policy_uri,
                allowed_cors_origins: body.client.allowed_cors_origins || null,
                tos_uri: body.client.tos_uri,
                client_uri: Array.isArray(body.client.redirect_uris) && body.client.redirect_uris[0] || '',
                logo_uri: body.client.logo_uri,
                contacts: body.client.contacts || null,
                client_secret_expires_at: body.client.client_secret_expires_at,
                subject_type: body.client.subject_type,
                token_endpoint_auth_method: body.client.token_endpoint_auth_method,
                userinfo_signed_response_alg: body.client.userinfo_signed_response_alg,
                created_at: body.client.created_at || '',
                updated_at: body.client.updated_at,
            })

            const {challenge: uuid, subject, ...bodyRest} = body

            const challengeParams: ChallengeInterface = {
                uuid,
                ...bodyRest,
                requested_scope: ["i7TBEho8TUPg4ESPmGRiiDMGF55QJM37Xk"], //TODO: this should be configurated and come from the client app that is registered on hydra
                client: challengeClient
            }
            
            const loginConsentChallenge = new Challenge(challengeParams);

            const {signature = ''} = await verusClient['vrsctest'].post('', {
                jsonrpc: '2.0',
                method: 'signmessage',
                params: [
                    process.env.CONSENT_NODE_VERUS_IDENTITY,
                    loginConsentChallenge.toString()
                ]
            }).then(res => res.data.result).catch(err =>  err.response.data.error);
            
            const verusIdSignature = new VerusIDSignature({signature
            }, LOGIN_CONSENT_REQUEST_SIG_VDXF_KEY);

            const loginConsentRequest = new LoginConsentRequest({
                chain_id: "VRSCTEST",
                signing_id: process.env.CONSENT_NODE_VERUS_IDENTITY || '',
                signature: verusIdSignature,
                challenge: loginConsentChallenge,
            });



            // console.log(util.inspect(body, false, null, true /* enable colors */))
            console.log(util.inspect(loginConsentRequest, false, null, true /* enable colors */))

            const walletRedirectUrl = `${WALLET_VDXF_KEY.vdxfid}://x-callback-url/${LOGIN_CONSENT_REQUEST_VDXF_KEY.vdxfid}/?${LOGIN_CONSENT_REQUEST_VDXF_KEY.vdxfid}=${base64url.encode(loginConsentRequest.toString())}`
                    
            console.log("signature", signature)
            console.log("link", walletRedirectUrl)
            res.redirect(String(walletRedirectUrl))
        })
        // This will handle any error that happens when making HTTP calls to hydra
        .catch(next)
});

export default router


