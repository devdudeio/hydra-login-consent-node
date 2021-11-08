import {AdminApi, Configuration} from '@oryd/hydra-client'
import axios from "axios";

const baseOptions: any = {}

if (process.env.MOCK_TLS_TERMINATION) {
    baseOptions.headers = {'X-Forwarded-Proto': 'https'}
}

const hydraAdmin = new AdminApi(
    new Configuration({
        basePath: process.env.HYDRA_ADMIN_URL,
        baseOptions
    })
)

const vrsctest = axios.create({
    baseURL: process.env.VRSCTEST_RPC_URL,
    auth: {
        username: process.env.VRSCTEST_RPC_USER || '',
        password: process.env.VRSCTEST_RPC_PASSWORD || '',
    }
});

const verusClient = {
    vrsctest,
    // add more verus pbaas chain clients here
}

export {hydraAdmin, verusClient}
