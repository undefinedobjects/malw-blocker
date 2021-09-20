
const ENDPOINT_URL = 'https://safebrowsing.googleapis.com/v4/'
const DEFAULT_CLIENT_ID = 'safe-browsing-api-js-client'
const DEFAULT_CLIENT_VERSION = '1.0.0'

const ThreatTypes = {
    THREAT_TYPE_UNSPECIFIED: 'THREAT_TYPE_UNSPECIFIED',
    MALWARE: 'MALWARE',
    SOCIAL_ENGINEERING: 'SOCIAL_ENGINEERING',
    UNWANTED_SOFTWARE: 'UNWANTED_SOFTWARE',
    POTENTIALLY_HARMFUL_APPLICATION: 'POTENTIALLY_HARMFUL_APPLICATION',
}

const PlatformTypes = {
    PLATFORM_TYPE_UNSPECIFIED: 'PLATFORM_TYPE_UNSPECIFIED',
    WINDOWS: 'WINDOWS',
    LINUX: 'LINUX',
    ANDROID: 'ANDROID',
    OSX: 'OSX',
    IOS: 'IOS',
    ANY_PLATFORM: 'ANY_PLATFORM',
    ALL_PLATFORMS: 'ALL_PLATFORMS',
    CHROME: 'CHROME',
}

const ThreatEntryTypes = {
    THREAT_ENTRY_TYPE_UNSPECIFIED: 'THREAT_ENTRY_TYPE_UNSPECIFIED',
    URL: 'URL',
    EXECUTABLE: 'EXECUTABLE',
}

class Client {
    apiKey = null
    clientId = null
    clientVersion = null

    constructor(apiKey, clientId = DEFAULT_CLIENT_ID, clientVersion = DEFAULT_CLIENT_VERSION) {
        if (!apiKey) throw new NoAPIKeyError()
        this.apiKey = apiKey
        this.clientId = clientId
        this.clientVersion = clientVersion
    }

    async lookup(urls, options = {}) {
        if (typeof urls === 'string') {
            urls = [urls]
        }
        const apiEndpoint = `${ENDPOINT_URL}threatMatches:find?key=${this.apiKey}`
        const body = {
            client: {
                clientId: this.clientId,
                clientVersion: this.clientVersion,
            },
            threatInfo: {
                threatTypes: options.threatTypes || Object.values(ThreatTypes),
                platformTypes: options.platformTypes || PlatformTypes.ANY_PLATFORM,
                threatEntryTypes: [ThreatEntryTypes.URL],
                threatEntries: urls.map(url => ({url})),
            }
        }
        const response = await fetch(apiEndpoint, {
            method: 'POST',
            body: JSON.stringify(body),
            headers: {
                'Content-Type': 'application/json',
            },
        })
        const jsonResponse = await response.json()
        const matches = jsonResponse.matches || []
        const matchedURLs = matches.map(match => match.threat?.url)
        return urls.reduce((acc, urlToLookup) => {
            acc[urlToLookup] = matchedURLs.includes(urlToLookup)
            return acc
        }, {})
    }
}

class NoAPIKeyError extends Error {}


let client = new Client('AIzaSyCuef5OcVIBRTKJ1TSv1NT6_JoSVF0crC8')

const close = async (details) => {

	return {

		cancel: await client.lookup(details.url).then(obj => obj[Object.keys(obj)[0]])

	}

}

const checkMalware = () => {

	chrome.webRequest.onBeforeRequest.addListener(
		close,
		{
			urls: [ "http://*/*", "https://*/*" ]
		},
		['blocking', 'requestBody']
	)

	chrome.browserAction.setIcon({ path: 'icons/icon16.png' })

}





chrome.browserAction.onClicked.addListener((tab) => {

	checkMalware();
	
})



