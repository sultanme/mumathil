import express from 'express'
import cors from 'cors'
import * as cheerio from 'cheerio'
import https from 'https'
import http from 'http'
import { URL } from 'url'
import dns from 'dns'
import { promisify } from 'util'
import tls from 'tls'

const app = express()
app.use(cors())
app.use(express.json())

const dnsResolve = promisify(dns.resolve4)

// ── Fetch a URL with timeout ──────────────────────────────────────────────────
function fetchPage(targetUrl, timeout = 10000) {
    return new Promise((resolve, reject) => {
        const parsedUrl = new URL(targetUrl)
        const client = parsedUrl.protocol === 'https:' ? https : http
        const req = client.get(targetUrl, {
            headers: {
                'User-Agent': 'Mozilla/5.0 (Mumtathil PDPL Scanner/1.0)',
                'Accept': 'text/html,application/xhtml+xml',
                'Accept-Language': 'ar,en;q=0.9',
            },
            timeout,
            rejectUnauthorized: false,
        }, (res) => {
            // Follow redirects
            if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
                const redirectUrl = new URL(res.headers.location, targetUrl).href
                fetchPage(redirectUrl, timeout).then(resolve).catch(reject)
                return
            }
            let data = ''
            res.on('data', chunk => data += chunk)
            res.on('end', () => resolve({ html: data, statusCode: res.statusCode, headers: res.headers }))
        })
        req.on('error', reject)
        req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')) })
    })
}

// ── Get TLS info ──────────────────────────────────────────────────────────────
function getTlsInfo(hostname) {
    return new Promise((resolve) => {
        const socket = tls.connect(443, hostname, { rejectUnauthorized: false, servername: hostname }, () => {
            const cert = socket.getPeerCertificate()
            const protocol = socket.getProtocol()
            const cipher = socket.getCipher()
            resolve({
                valid: socket.authorized,
                protocol: protocol,
                cipher: cipher?.name,
                issuer: cert?.issuer?.O,
                validTo: cert?.valid_to,
            })
            socket.end()
        })
        socket.on('error', () => resolve(null))
        socket.setTimeout(5000, () => { socket.destroy(); resolve(null) })
    })
}

// ── Check data hosting location ──────────────────────────────────────────────
async function checkHostingLocation(hostname) {
    try {
        const ips = await dnsResolve(hostname)
        const ip = ips[0]
        // Try to get geo info from a free API
        const geoRes = await new Promise((resolve, reject) => {
            http.get(`http://ip-api.com/json/${ip}?fields=country,countryCode,isp,org,hosting`, (res) => {
                let data = ''
                res.on('data', chunk => data += chunk)
                res.on('end', () => { try { resolve(JSON.parse(data)) } catch { resolve(null) } })
            }).on('error', () => resolve(null))
        })
        return { ip, geo: geoRes }
    } catch {
        return null
    }
}

// ── Run all checks ────────────────────────────────────────────────────────────
async function runScan(targetUrl) {
    const results = []
    let html = ''
    let $
    let fetchSuccess = false
    let tlsInfo = null
    let hostingInfo = null
    const parsedUrl = new URL(targetUrl)

    // Step 1: Fetch the page
    try {
        const res = await fetchPage(targetUrl)
        html = res.html
        $ = cheerio.load(html)
        fetchSuccess = true
    } catch (err) {
        // Still run checks that don't need HTML
    }

    // Step 2: Get TLS info
    if (parsedUrl.protocol === 'https:') {
        tlsInfo = await getTlsInfo(parsedUrl.hostname)
    }

    // Step 3: Get hosting info
    hostingInfo = await checkHostingLocation(parsedUrl.hostname)

    // ── CHECK 1: HTTPS ──────────────────────────────────────────────────────────
    const isHttps = parsedUrl.protocol === 'https:'
    results.push({
        id: 'https',
        name: 'بروتوكول HTTPS',
        icon: '🔒',
        category: 'أمان',
        weight: 12,
        passed: isHttps,
        passMsg: 'الموقع يستخدم بروتوكول HTTPS لتشفير الاتصال.',
        failMsg: 'الموقع لا يستخدم HTTPS! البيانات المنقولة غير مشفرة وهذا مخالف للمادة 22 من نظام PDPL.',
        recommendation: 'يجب تفعيل شهادة SSL/TLS فوراً لتشفير جميع البيانات المنقولة.',
        details: isHttps && tlsInfo ? `البروتوكول: ${tlsInfo.protocol || 'N/A'} | التشفير: ${tlsInfo.cipher || 'N/A'} | المُصدِر: ${tlsInfo.issuer || 'N/A'}` : null,
    })

    // ── CHECK 2: TLS Strength ───────────────────────────────────────────────────
    const strongTls = tlsInfo && (tlsInfo.protocol === 'TLSv1.3' || tlsInfo.protocol === 'TLSv1.2')
    results.push({
        id: 'tls_strength',
        name: 'قوة تشفير TLS',
        icon: '🔐',
        category: 'أمان',
        weight: 10,
        passed: strongTls,
        passMsg: `مستوى التشفير ${tlsInfo?.protocol || 'TLS'} مُفعّل ويفي بالمعايير الأمنية المطلوبة.`,
        failMsg: tlsInfo ? `مستوى التشفير ${tlsInfo.protocol} ضعيف أو قديم.` : 'تعذّر فحص مستوى التشفير (الموقع لا يدعم HTTPS).',
        recommendation: 'فعّل TLS 1.2 على الأقل (يُفضل TLS 1.3) واستخدم تشفير AES-256.',
        details: tlsInfo ? `البروتوكول: ${tlsInfo.protocol} | صالح حتى: ${tlsInfo.validTo || 'N/A'}` : null,
    })

    // ── CHECK 3: Privacy Policy Page ────────────────────────────────────────────
    let hasPrivacyPolicy = false
    let privacyPolicyUrl = null
    if (fetchSuccess && $) {
        const privacyKeywords = ['privacy', 'خصوصية', 'الخصوصية', 'privacy-policy', 'سياسة-الخصوصية', 'بيانات شخصية']
        $('a').each((_, el) => {
            const href = $(el).attr('href') || ''
            const text = $(el).text() || ''
            const combined = (href + ' ' + text).toLowerCase()
            if (privacyKeywords.some(kw => combined.includes(kw))) {
                hasPrivacyPolicy = true
                privacyPolicyUrl = href
            }
        })
        // Also check for meta tags or footer content
        const bodyText = $('body').text().toLowerCase()
        if (bodyText.includes('سياسة الخصوصية') || bodyText.includes('privacy policy')) {
            hasPrivacyPolicy = true
        }
    }
    results.push({
        id: 'privacy_policy',
        name: 'صفحة سياسة الخصوصية',
        icon: '📜',
        category: 'الشفافية',
        weight: 15,
        passed: hasPrivacyPolicy,
        passMsg: `تم العثور على صفحة/رابط سياسة الخصوصية في الموقع.${privacyPolicyUrl ? ` (${privacyPolicyUrl})` : ''}`,
        failMsg: 'لم يتم العثور على صفحة سياسة خصوصية واضحة. هذا مخالف للمادة 12 من نظام PDPL.',
        recommendation: 'يجب إنشاء صفحة سياسة خصوصية شاملة تتضمن: أنواع البيانات المجمعة، الغرض، الأساس القانوني، وحقوق أصحاب البيانات.',
    })

    // ── CHECK 4: Cookie Consent Banner ──────────────────────────────────────────
    let hasCookieConsent = false
    if (fetchSuccess && $) {
        const cookieKeywords = ['cookie', 'cookies', 'كوكي', 'consent', 'موافقة', 'تعريف الارتباط', 'cookie-consent', 'cookie-banner', 'cookieConsent', 'gdpr', 'onetrust', 'cookiebot', 'cc-banner']
        const htmlStr = html.toLowerCase()
        hasCookieConsent = cookieKeywords.some(kw => htmlStr.includes(kw))
        // Check common cookie consent script sources
        $('script').each((_, el) => {
            const src = $(el).attr('src') || ''
            if (src.includes('cookiebot') || src.includes('onetrust') || src.includes('cookie') || src.includes('consent')) {
                hasCookieConsent = true
            }
        })
    }
    results.push({
        id: 'cookie_consent',
        name: 'إشعار الكوكيز والموافقة',
        icon: '🍪',
        category: 'الموافقات',
        weight: 10,
        passed: hasCookieConsent,
        passMsg: 'يوجد بانر موافقة على الكوكيز أو آلية إدارة الموافقة في الموقع.',
        failMsg: 'لا يوجد إشعار موافقة على ملفات تعريف الارتباط. المادة 5 تتطلب الحصول على موافقة صريحة.',
        recommendation: 'أضف بانر كوكيز يوضح أنواع الكوكيز المستخدمة ويتيح للمستخدم القبول أو الرفض.',
    })

    // ── CHECK 5: Third-party Trackers ───────────────────────────────────────────
    const trackers = []
    if (fetchSuccess && $) {
        const trackerDomains = {
            'google-analytics.com': 'Google Analytics',
            'googletagmanager.com': 'Google Tag Manager',
            'facebook.net': 'Facebook Pixel',
            'connect.facebook.com': 'Facebook SDK',
            'doubleclick.net': 'Google DoubleClick',
            'hotjar.com': 'Hotjar',
            'mixpanel.com': 'Mixpanel',
            'segment.com': 'Segment',
            'amplitude.com': 'Amplitude',
            'tiktok.com': 'TikTok Pixel',
            'snap.com': 'Snapchat Pixel',
            'twitter.com/i/': 'Twitter Pixel',
        }
        $('script').each((_, el) => {
            const src = $(el).attr('src') || ''
            for (const [domain, name] of Object.entries(trackerDomains)) {
                if (src.includes(domain)) trackers.push(name)
            }
        })
        // Check inline scripts
        const scriptText = html
        for (const [domain, name] of Object.entries(trackerDomains)) {
            if (scriptText.includes(domain) && !trackers.includes(name)) trackers.push(name)
        }
    }
    const hasUndisclosedTrackers = trackers.length > 0 && !hasPrivacyPolicy
    results.push({
        id: 'third_party_trackers',
        name: 'متتبعات الطرف الثالث',
        icon: '👁️',
        category: 'الخصوصية',
        weight: 10,
        passed: trackers.length === 0 || (trackers.length > 0 && hasPrivacyPolicy),
        passMsg: trackers.length === 0
            ? 'لم يتم اكتشاف متتبعات طرف ثالث.'
            : `تم اكتشاف: ${trackers.join('، ')}. يبدو أنه تم الإفصاح عنها في سياسة الخصوصية.`,
        failMsg: `تم اكتشاف متتبعات طرف ثالث (${trackers.join('، ')}) بدون إفصاح أو سياسة خصوصية واضحة.`,
        recommendation: 'يجب الإفصاح عن جميع المتتبعات في سياسة الخصوصية والحصول على موافقة المستخدم وفقاً للمادة 5.',
        details: trackers.length > 0 ? `المتتبعات المكتشفة: ${trackers.join('، ')}` : null,
    })

    // ── CHECK 6: Data Collection Forms ──────────────────────────────────────────
    let formCount = 0
    let formsWithConsent = 0
    if (fetchSuccess && $) {
        const forms = $('form')
        formCount = forms.length
        forms.each((_, form) => {
            const formHtml = $(form).html() || ''
            const formText = $(form).text() || ''
            const combined = (formHtml + formText).toLowerCase()
            if (combined.includes('أوافق') || combined.includes('موافق') || combined.includes('consent') ||
                combined.includes('agree') || combined.includes('privacy') || combined.includes('خصوصية') ||
                combined.includes('checkbox') || combined.includes('terms')) {
                formsWithConsent++
            }
        })
    }
    const formsPassed = formCount === 0 || formsWithConsent >= Math.ceil(formCount * 0.5)
    results.push({
        id: 'data_forms',
        name: 'نماذج جمع البيانات',
        icon: '📝',
        category: 'الموافقات',
        weight: 12,
        passed: formsPassed,
        passMsg: formCount === 0
            ? 'لم يتم العثور على نماذج جمع بيانات في الصفحة الرئيسية.'
            : `تم العثور على ${formCount} نموذج/نماذج، و ${formsWithConsent} منها تتضمن آلية موافقة.`,
        failMsg: `تم العثور على ${formCount} نموذج/نماذج لجمع البيانات، لكن ${formCount - formsWithConsent} منها بدون إشعار خصوصية أو خانة موافقة.`,
        recommendation: 'أضف فقرة إشعار الخصوصية وخانة "أوافق على سياسة الخصوصية" لكل نموذج يجمع بيانات شخصية.',
        details: formCount > 0 ? `النماذج: ${formCount} | مع موافقة: ${formsWithConsent}` : null,
    })

    // ── CHECK 7: Data Hosting Location ──────────────────────────────────────────
    const isSaudiHosted = hostingInfo?.geo?.countryCode === 'SA'
    results.push({
        id: 'data_hosting',
        name: 'موقع استضافة البيانات',
        icon: '🌐',
        category: 'توطين البيانات',
        weight: 15,
        passed: isSaudiHosted,
        passMsg: `الموقع مستضاف داخل المملكة العربية السعودية.${hostingInfo?.geo?.isp ? ` (${hostingInfo.geo.isp})` : ''}`,
        failMsg: `الموقع مستضاف خارج المملكة${hostingInfo?.geo?.country ? ` (${hostingInfo.geo.country})` : ''}. المادة 29 تشترط توطين البيانات الشخصية داخل المملكة.`,
        recommendation: 'انقل الاستضافة إلى مزود سحابي داخل المملكة (STC Cloud, Alibaba Cloud الرياض) أو احصل على إذن نقل.',
        details: hostingInfo ? `IP: ${hostingInfo.ip} | الدولة: ${hostingInfo.geo?.country || 'غير معروف'} | المزود: ${hostingInfo.geo?.org || hostingInfo.geo?.isp || 'غير معروف'}` : null,
    })

    // ── CHECK 8: DPO Contact ────────────────────────────────────────────────────
    let hasDpoContact = false
    if (fetchSuccess && $) {
        const dpoKeywords = ['dpo', 'data protection officer', 'مسؤول حماية البيانات', 'حماية البيانات', 'مسؤول الخصوصية', 'privacy officer']
        const bodyText = $('body').text().toLowerCase()
        hasDpoContact = dpoKeywords.some(kw => bodyText.includes(kw))
    }
    results.push({
        id: 'dpo_contact',
        name: 'معلومات مسؤول حماية البيانات',
        icon: '👤',
        category: 'الشفافية',
        weight: 8,
        passed: hasDpoContact,
        passMsg: 'تم العثور على إشارة لمسؤول حماية البيانات الشخصية في الموقع.',
        failMsg: 'لم يتم العثور على معلومات مسؤول حماية البيانات في الموقع.',
        recommendation: 'يجب تعيين مسؤول حماية بيانات (DPO) وإتاحة بيانات التواصل معه بشكل واضح في الموقع.',
    })

    // ── CHECK 9: User Rights Mechanism ──────────────────────────────────────────
    let hasRightsMechanism = false
    if (fetchSuccess && $) {
        const rightsKeywords = ['حق الوصول', 'طلب حذف', 'data request', 'subject request', 'dsar', 'حقوقك', 'your rights', 'حقوق أصحاب', 'طلب بياناتك', 'right to access', 'right to delete']
        const bodyText = $('body').text().toLowerCase()
        hasRightsMechanism = rightsKeywords.some(kw => bodyText.includes(kw))
    }
    results.push({
        id: 'user_rights',
        name: 'آلية ممارسة حقوق أصحاب البيانات',
        icon: '⚖️',
        category: 'حقوق أصحاب البيانات',
        weight: 10,
        passed: hasRightsMechanism,
        passMsg: 'يوجد إشارة لحقوق أصحاب البيانات أو آلية لممارستها في الموقع.',
        failMsg: 'لا توجد آلية واضحة لأصحاب البيانات لطلب الوصول أو حذف بياناتهم. مخالف للمواد 6-8 من PDPL.',
        recommendation: 'أنشئ نموذجاً إلكترونياً (Data Subject Request Form) يتيح للمستخدمين طلب الوصول/التصحيح/الحذف.',
    })

    // ── CHECK 10: Retention Notice ──────────────────────────────────────────────
    let hasRetentionNotice = false
    if (fetchSuccess && $) {
        const retentionKeywords = ['retention', 'الاحتفاظ', 'مدة الاحتفاظ', 'data retention', 'حذف البيانات', 'deletion', 'فترة الاحتفاظ', 'نحتفظ بالبيانات']
        const bodyText = $('body').text().toLowerCase()
        hasRetentionNotice = retentionKeywords.some(kw => bodyText.includes(kw))
    }
    results.push({
        id: 'retention_notice',
        name: 'إشعار مدة الاحتفاظ بالبيانات',
        icon: '⏳',
        category: 'الشفافية',
        weight: 8,
        passed: hasRetentionNotice,
        passMsg: 'يوجد إفصاح عن مدد الاحتفاظ بالبيانات وسياسة الحذف.',
        failMsg: 'لا يوجد إفصاح عن مدة الاحتفاظ بالبيانات. المادة 18 تلزم بعدم الاحتفاظ بالبيانات أكثر من اللازم.',
        recommendation: 'أضف قسماً في سياسة الخصوصية يوضح مدة الاحتفاظ لكل نوع من البيانات ومتى يتم حذفها.',
    })

    // Calculate total score
    const totalWeight = results.reduce((s, c) => s + c.weight, 0)
    const passedWeight = results.filter(c => c.passed).reduce((s, c) => s + c.weight, 0)
    const score = Math.round((passedWeight / totalWeight) * 100)

    return {
        url: targetUrl,
        score,
        checks: results,
        passedCount: results.filter(c => c.passed).length,
        failedCount: results.filter(c => !c.passed).length,
        totalChecks: results.length,
        fetchSuccess,
        timestamp: new Date().toISOString(),
    }
}

// ── API Endpoint ──────────────────────────────────────────────────────────────
app.post('/api/scan', async (req, res) => {
    const { url } = req.body
    if (!url) return res.status(400).json({ error: 'URL is required' })

    try {
        let targetUrl = url
        if (!targetUrl.startsWith('http')) targetUrl = `https://${targetUrl}`
        new URL(targetUrl) // validate

        console.log(`🔍 Scanning: ${targetUrl}`)
        const results = await runScan(targetUrl)
        console.log(`✅ Scan complete: ${results.score}% (${results.passedCount}/${results.totalChecks} passed)`)
        res.json(results)
    } catch (err) {
        console.error('Scan error:', err.message)
        res.status(500).json({ error: `فشل الفحص: ${err.message}` })
    }
})

app.get('/api/health', (_, res) => res.json({ status: 'ok', service: 'Mumtathil Scanner API' }))

const PORT = 3001
app.listen(PORT, () => {
    console.log(`\n🛡️  Mumtathil Scanner API running on http://localhost:${PORT}`)
    console.log(`   POST /api/scan  { "url": "https://example.com" }\n`)
})
