/*
 * Copyright (C) 2023 Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */
package didjwk

// An example did:jwk from https://github.com/quartzjer/did-jwk/blob/6520a0edc8fa8f37c09af99efe841d54c3ca3b3b/spec.md
const canonicalJWK = `{"crv":"P-256","kty":"EC","x":"acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0","y":"_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE"}`

// Valid JSON which is not a valid JWK
const validJSONInvalidJWK = `{"json": "this valid JSON is not a JWK"}`

const rsa2048JWKWithPrivateKey = `{
    "p": "0_Eh8fgryISKMIRlUel3sKJaL30FM6bZR-6Z38nhxnbO38q0Db_MNS1Kp8Hkb6O5LsplSoIwx2i5U6q-6uFuKYBm0cYBf3oYOyn68THXnHnNhQwXaFseqE20gtsJScIAE8cLf9SKCQExy9dLjOMCTaERH-f_8mEVf9oKhCTUGJc",
    "kty": "RSA",
    "q": "sl4gFrs8xOaJYWlrN5Y2VJgra5wGx91YILfbE4CNwpAKUjkHwu3kLkkjc4t4Kio4j3ubwKDZdqftwvGFHf0bSSs3iWxdBL9q7HDOT20pghNg3AMbL-GBHLERA6c6dZi0cLXhNRIgiCPrFyZOpwRsazoCxzHwfLFnuKLqEVTwJ3c",
    "d": "QUx7FFJ41A7vI2P9y3oStMmQgtUregj15bw7HQwjLqRJj5sFaOmM2d_XOodkBn5bYPZU8cdp7AKCT7rFwhtubs62fO-VzyhT3ZZEt2G_FrIpsdVdB1QElttdeo5RnwCbFW_VX67HGre-BsI_tiY7RPTAX8QZ31vbePLukIoGedFMwJlI1WWMwQ4LvZyxKWbNjs2I4bAQGMMg_F04Llos2rSRgo22DgbKs4W12uguuPCJQBd2HvvvAqLKM62--15Ah5PRsUFKFMyvwCN5uSUv-ThEqkWAbomNut8--XQ62ZiE6WlKZtxu8526j6p5kHhkNWTTNUe86vopXDOGfm93UQ",
    "e": "AQAB",
    "qi": "YgzXcdeHJVwqUGwG5c3dJCVZNDz_JmdUOgSWysbJqajgGgvp1-Fgvpcdgn0FQ-fuq2IjQOmAXN9PDlkRnk81Pg6DepYiyDmEiC_es6xwZZRt_Ieox483sNmEbdI4VqEheglfYK2gLC8bMWFKeMUAYHey2A3dov7WUzTaOkdBUmw",
    "dp": "LV5n4tE6JiFhJ4Of4Mn2aiRG4_WCQI1N490KqWIg54gVPsi4hFzzTMrWOVUDHnbQtFh1GF8ILBeZ3HQnjEYXe-DVocAeH_i16SxSYIFH42IbgYiWFiuzQ1nm80AKG_TgaVtpdcK8jbLowvbiYFVT7-Qzsz3Jh0wK-yRkreboVB8",
    "dq": "T1gBjDsUKD6pBBUh5aNDXdQnFIJenc-_oSZIJN-9r7vla3gFFNg_9bsBMyfqd086w9DnkwO6WMcQw_QuFA4AckbwOIhkxHTl-nGfxMM5gKxgHN6g3GbCyWGWwPpFzgP02GJ_4NzEbesUa8LVoAQeuoAetj9nzAAatI578uPGxLc",
    "n": "k6uWtatiLqPE8N56Uvb5PbJhkAoFJt8-ft7UBQLLIORVr4xJrBswHuyKUi0lHjtzFEML-r0As5wzLzd9F7hYkY3GOYIFSgKACNo_XqXrFfQzn71rWlwwAosvuAV6e1Z7g0tSttvFbaIoVsjUOUtzv9UUf6sj90mgkWxwHMSF4cHo1u0IBI7WwsRAKVJztznCkPFNoySpcO3CHP0rpVZetBtqHkxpAQ0T8dKTTejk3YU24Fo2aH2pybdrnLmCv6FDO2YLPmjLBL8obLPtPJZrG5ULCrGll_tcBP_F-eakqEtrPZ_REGvvPeNzoMB7KjJycw-9ElU6V2tGCsv5B-ZvMQ"
}`

const rsa4096JWKWithPrivateKey = `{
    "p": "-6-_S3jYfUrKDz2LeM8ai1LiJH-BgNbGyH-IokiYsTXAJwKPMjLDHseDL12kR3OSvqr3VoLsCEHXI69wmTf1XZA2P-ZOAbZOtkomwKaSML_t4WU46q7qe8I5AX19iKyK9F4de_j5ZTQctOErOqBjLLblaQ2m1Fv7sLRz3d41oWesftiZf-m2f97TQpBSxKWWBrPOIH-Jwtp5RqloHd2J7KpaKvvm4O6Rjv5Su929qS0uxaJNfIZGukQONy8gN0WOX5psnodcDbdDO86qxkFPW-BMu4odPl9SoAWs9m7kSjxxfYnPJKUBgq_lZUaJZROdWWK1CcE0cBV0xkgvmYse3Q",
    "kty": "RSA",
    "q": "z87uJHDKfPQPbNSM2CDOKQXrJZxIDquMHdkIK_D-dqACR4L8wWi_ggSpvqFP0GyQ86Bwk_QkLUzKx4rXSfgKbJD237Z-io0pWLs2MxmQ_MDqycH-dTThZ6cqfWQxU5ZBd47l-QO8V2VB0MsFs3kApNDisLmOqaQznH8PIpC-QhkHNxisVPkwSt5ukgbwIy5NIxWaxMdPffOD1I5VyYpiO4zwJuCqMRlxyGTOlIOkmNjfhbn9hfaEYMattRsjUVO4A-o9KNFlSpjK2jzWASeshIpgPwx8J8ap2kOFY49irCMbQA013xLW5R9_Fp-QDlDgxfiSKVcIBIA-qQMH16GH9Q",
    "d": "eBu165P5PbqqRo693iVv_F2qFExhtYiw0LTKoOj_VefmpHwf1iK5-brYgG7QsOL9QbbE5oAWiG1OoY7yOzl5zGEpW9RpfrcVtBBqSRHVHHULu9Fa-Nrp9ZghEZM5scp9giAvd9Ot0qZBP5IW9PcRAf6GQ5AH3-NhTQinrCstkMS1msFPtKN4cPIhbo8antKMKeHK0i6UFh-N9qE18yxoGpDupcPbBVGjijVziC5givIrlxTq2ZUY2brvAGaH_R_isE-zGDhzhBVmONMMmqJZi7Sxyh2qTOjKzE_LDrNlX4JkMu-T4t72TwEqIUxeRWuaCnD2JGFKCZ4fIlLSluokQLzCzqpdrSep88unubPw6J-gOdJh6DzFuIlwnJkOSEJOTzDcoqlILIrufzQU98p-SxvMzc7h0T72bfViikqMqsWb0ueFLa864Np6UnJBUxAYNymK4aw-ozX6wUrJBeiCWP8z_jAsT3YWtzqoSKC9HVKUZWtQ7w9V2zidQZfplB8XeyVZrK2umYVutPc7yvdAJHpDWHZXqhhKmk07p2cubl0XjM1EawkKNNQnDBcnykutwDnLwQ7Pp7RnA4aTSuT40RwWEd_zvXCWGUOGGi519zAS7ImTYYu4_NbbKroCy8Dg_akUJlZc5cUyVl3dC2tJ59A5B6EAA9oYYscwhPf6-AE",
    "e": "AQAB",
    "qi": "OEcW61dW2XLblrGlh1qNzK2nOsBjtWbhgptYmEmmGF5XS-wBKuKeTs6WWDr10Lb6CbPrZQLeq29W_Hba5G6iOi0BZdYmrCQaAAK32DRUvcGrAp71bsncFflTHRhXlvtZor7APGCW2dZoS2a_y2LmObxH6hB-19y1Ypca5HwZHXG6r9nKzYGaEKXpBSOhIg8QL79DBZtBjWNPIh2Bus4pspGWYkZZ_vya_CpcW_ga1UL5FMX-VRMFXOS2bI7kxCNPHkvSdDVwHIo2dwA_FlgGfplIFXfXt0x3x9oI8Ow2wam8UvTcPqbeHZwsVjtSwzVDliMz9CDwUrEXEFcAjQrYcA",
    "dp": "B-ZPQcYsPVqAlxPecc9GTQMv9-dMoEede6ONHVLcAAvo2RCaf__Z4fhvJKhyxI9bFsL0-nEniWbPot4Z0aVQ_TvOiBjpb-JR_CS9rKRNyFvt0npD3BHbaEEDWwmeTBDmV58wm7iH02ZcVE0Q90kbc8bV0oNMLjQo5TX0wQz9b_B6GI0h3ELwqHjM9rTi9CsiV1mDab-3CjejQNWGYBGZB6WdKOY5K-wxA2T2IdFm5410f12FwxfP1n7WV2MSRsnXGycUq7Eh8YhEAveMoqZgIEkc_3HpUxDY3g7vi9iVL8NP6JnPt526O2jb8V7SZyrDcI_JkOHQjIgP3z1ayR31vQ",
    "dq": "Uq4XTAJgXiTQulE7FIbA38uOCnHKraONZRbDzI_e_p2dKoywOdeOUpG-Y61Uzy1S4svT3toFRszF5WyVScXZh-aJgureIAwYBki-QMiMSjQLdmir8EAw6oe1PRyPD525wHLnhxL4baFI9WTBiO281taRSxUY8N_29O4MvIjwWeYRW9eCQXC_yRoEzi7afnTelfXzlRVjyE4KBpj3Au__M4hYyG8c59oizkNleeuCopmvHUqp1xIFC2ghFuyMOcBgd5ZL7SCa93ohQ4Fu-Bir6DQSJSO3hi_hxoiU2s7iyHBTWEGpTG73d0P30a18qGV_eOT0amRJOVk5FQ-yoBWRvQ",
    "n": "zE6NOyzlU7GYP1DTpagRPA0DTwhwR0xf2Y1dRhV6CgqbuTbix3V5z3KDXuESEjQv3y0ez_rglpBQC62iFmdDOnAylaxC5CZoeQYnt66NfYQYI30suBDQ6DMuNDpVgidv7KLGU16nzYdch8hxKcSBOsmfe3hr6AxXEpCCeiv4vmuhYOV9zpX8u9FYPmisGxc_w36mMUj4zVAvxnrEmb5Egu4zZLHCZltGWeTE3-gICQ34aDB9wenMAWg-ewpDAEPTdNpjWSqaV6ka4pzz-KhR9DAJWPrR7kQyiEGkxifk6OAhhhW7qE-wW8wS8KC9x4Ho-Gsqqq48PsdJkjFBVyeEHoGGaGv0bJTDtbHVvsW9EaNlTaAxcHZMq-Cqd1rXlEoBQEzK_fUq9tkcMI-5gQ9N_0xkxaeXmIG6Tm-W-6RnNerq6EFeAMbKzhnVLuVsZg6_Z_09Z15nTRakA9n0FGYYtXfrS5B8SEBBN_CemuCHhD3fwUt33NRb5WeERUTCmBesQHJ3WJdoDWj8lQGQ5bCefX3TUJ1N3j_hCSvyxqPvuFpvRry2qxmdQue7XvaSgn5bL00kIDxusnfYE2bp2St-axlcJQjfVEwcPXWCWE3laCSGFO3Ui_9qFT9V9vUWISO_OJuwNjNeF5GlDP2EJCMpgoxwRhjHrwVba8cF-1NoFIE"
}`

const ec256JWKWithPrivateKey = `{
    "kty": "EC",
    "d": "qoJ3auF6N770x0zroZHZ0JmfnSiigXIC-u7mwA8CboQ",
    "crv": "P-256",
    "x": "DBYUwN-LRg4Q59_iEQ0mUXAUWhHqalcFVthlDWmT_f8",
    "y": "wZjylDBAtC-Sg0IpkIVZ5p2lFo3geYVTTj18EalPNPI"
}`

const ec384JWKWithPrivateKey = `{
    "kty": "EC",
    "d": "TlDUevaJOUzPocPxHkYXwbueTpi6TlTK0iKLHxoAA5DQbOLaWovsSHgQim0Bph45",
    "crv": "P-384",
    "x": "pIGQ4EPTJAa2JsTP2RIBEz73St-SbtDxWGZtXUx_P64PrUHL1E08qbXkeGdDRUiL",
    "y": "g4DvG6uh6u3O3LVEhX9ou73acBwQUa08h0wO4WReYhKj6VSpV7zeJ2LY6U6w6kT_"
}`

const ec521JWKWithPrivateKey = `{
    "kty": "EC",
    "d": "Ab6MhntiWSzy916zDpW1l1c7AfSKdz8j-LLht3M2jHZ39-3xv7VIyqOgRr4crAool61Ci4udwGtVgQhN5D9S1eHv",
    "crv": "P-521",
    "x": "Ab_tNGp2O5EqdMQ3ow2Fpy1jQM_rZsCOSCvf7uRYumM8R9OTn9P4c52_iTc0ce8ra87YYG-4p1bDuhdNrhFHytRD",
    "y": "AfgkjDVsE9wNuHshxtHMXShtL3rNt3XfWOcL_NfNwVY1bCMrcUgTUUoC0ouU0eQIZQ5mMipU_EjlSJnAEdypR4jN"
}`

const ed25519JWKWithPrivateKey = `{
    "kty": "OKP",
    "d": "XdluFsGwtlPk-TaIHFXeXKcTB3O4IwjnRMHMKrjnTMQ",
    "crv": "Ed25519",
    "x": "xsX_imAPPsfj3Oyb8_DDSbV67mmZ8uSqusoTW91XOvo"
}`

const x25519JWKWithPrivateKey = `{
    "kty": "OKP",
    "d": "5ujXUK8CTwkDOzKKp81-ZnkQnF_GVuhgM4nIqW46ybA",
    "crv": "X25519",
    "x": "Kkm-lOPbHjs8FREsPxV1q6iYx9tDMPRNeL8k0lT5PwY"
}`
