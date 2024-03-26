/*
 * Copyright (C) 2021 Nuts community
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

package test

// ValidIrmaContract2 is a contract with more attributes that ValidIrmaContract like name and email
const ValidIrmaContract2 = `
{
  "@context": "https://irma.app/ld/signature/v2",
  "signature": [
    {
      "c": "yIAiQyBhpME2mOEMxLzXur/Kik5+9z9w/CP8z3HWHRc=",
      "A": "RlJ2zRDAJR1GTf0Bm05sDMKw3vGON9VGvH4Y1v+gXdbI71Nh1ReUfsUd2ACurCx2TtKVc6XqylF1G70NimJdt2sA3ItfYz3R5+TxXypwTfCYbXz8AYlgG+MRowzM45xTqqfZMqS4Fs8oIrdAI9ayUeKFDpTQju8b/JpC+v8U5ww=",
      "e_response": "bTHAQd2FYOzTJL3BbWZg2DeW91o9b1WAmQPWnJTwrDYNVHkZ6NVgo1V9paGMtX7OySN5yvO3gR1u",
      "v_response": "BbFK6CKsKnBzCzjYuAAUB9mZfJZ6OA0rnd+mCviL5hlu4v7DXdNrFWyIOqBDfeUce2vESyJnGi59JAbCfLROGK9Ehp+sRTbTvBHazZk5coyalz18nlARj+yi6pnORuU+nAMBhTpQXhnewNSQATuDOTS+KB1mY02Um3KQVXT1jLRhAJlU5yM0jnt1kuuRGh/tTCWmp0TMt5pS3J3yLS1ob909nuJB8Iv6Eaco2YGCFuc6gqNXtTGEhcG4CEHVe7MqLYPh9BC9Uk4bQiTeafZ9d88FBG1Uk2PBvrZMFItFDRmzWnYWU9MiMRSOBJzVtN6t2ofET9/HJ4mP5WfIcdo/",
      "a_responses": {
        "0": "ZyTWJl0205ubywYFH2bGPWp/71sOwAjMEr0ZHW1R9D7xK1tOFO9GYVI8CQ4tD6fZuHrHmwFWBy6QQA2EP9A8kSvuNR0A28MXOiY=",
        "10": "GamYIBWLPlPJ1woU0WrCQ9SQaDW3vK0ikUQCW0097ssuWC62mXm+a9AIjdSxa/AFTr8Q5N7bMkV08N640qdA5wpYgF/uN3Dlw/c=",
        "11": "mEym6gcrFps/XQihA/9gQWYEQszD3+101Kz04cBWJqcBtGl+qjq9ybtaCZiGBqlj8EKom5u6zC8DRsusxuKYCceU4kWKZjEI0I4=",
        "12": "3VZPNJ6xkThx2VJlDzCxCGVwin+6bSY5YwhKISVgphc9oeF8AyMkmKZkvV2JiwfUvNs7KpQlNyiLXw2s8iddpV8zLDlRHcHJDkE=",
        "13": "zieEles1/UQBuP/JH7fmYAAK/7ofiL5bkcUM49dPJaQGU7FuOzVZyBH1nSgocUr/IqhQTelzh2Yy0DDlS6JUSkP4FEhTDaoV4Bc=",
        "14": "GYDhalrXE0+7Qwzk/4Lyyz3kvZceT/gSB/Nxin4f+d4F3weuUnN13FvKDlARVEcIN427ex054dJxq1FtR2mjHK6HY1mmsFzYUi8=",
        "15": "kWH1kZCoiSz/EnbZh0GK7Nohte02KDnPsjjjMPIylSOCzqTi7YlaHy04YqypOLZWKXBHYMoNC6s9lEBpa8eQGMIKgBEOmfwXgj4=",
        "16": "8kO9SIYdGFr1j2dcw81E2poBNmPVCcdeuxMRBIIxVFj6yNOG/VT61B5NNlIruK2c3iLfGB5IzkHfggQiZ/qiamSfSjYeHo3BlRU=",
        "17": "wtN7WXZO7PC2bMpP+BTBIuW3ek4zIe9CagQIv8kZRueqZ8zJjTi6gfG+CmFV7Zv0Wnz1UaR4uk1UUIZM8PNKeFlOKef8t9wbcxU=",
        "18": "ncGLDudDnGucNaPd2KgAzAycVSs8RRtQCXknl7R9LUgf9xNyRT89Y6SdHOS82t9lijF1cnoBJWnafSAAEylqXTsBVDsKkM/ebcc=",
        "19": "iccLNvHK/WcVVUtr/NU59okczziBGyBL4ZlRfQ9tTQwpxnB3Qrew74AIVd+3mnx29NUxMw89Yp0sRqvLSKeQjoFYalD3sr9QLrE=",
        "2": "1TXHps+1ipZL8sb0yk+dQUVeV5Sps0FeRoL9TksPwEQ48zaB7+d3h0ery7ORjIN9F/X5/xfDoN4pTxylSzinkd1r6NrpVkN3sAQ=",
        "7": "r3/vPSuNl5g+azUiPfXXsao4PWuX1MsJgEAR6yQUXEctsokdBNQgprBulsofKMY3+emaW1KQatmIC99AQYO8p8qf8HdlnotrpPw=",
        "8": "OB7YmQXtpbRc/PBMCKIevou8GaAzQ1yx2995hPCNdA7Bzw83XInoQlUV381Tjn3GSi2bFFSEB06EfEvvM8qwcsEWrHjNzw+f5Ks=",
        "9": "PYVsNO5RP3BYMPDHlG88WArTKScAI70Zr7OVCkzIErnAL9AiaVgxGNeDhtsgC6ikHWqlEsalUDYs2vYXy68lYHpiSKT4FrL10VM="
      },
      "a_disclosed": {
        "1": "AwAKOAAaAADzEDKAtyC9EOmkzPGKMnV8",
        "3": "rtLY2MrWyw==",
        "4": "yMs=",
        "5": "hOTq0tTd",
        "6": "rtLY2MrWykDIykCE5OrS1N0="
      }
    }
  ],
  "indices": [
    [
      {
        "cred": 0,
        "attr": 6
      },
      {
        "cred": 0,
        "attr": 3
      },
      {
        "cred": 0,
        "attr": 4
      },
      {
        "cred": 0,
        "attr": 5
      }
    ]
  ],
  "nonce": "VShoLPhVET+5/jq1HyG70w==",
  "context": "AQ==",
  "message": "NL:BehandelaarLogin:v1 Ondergetekende geeft toestemming aan Demo EHR om namens Zorggroep Nuts en ondergetekende het Nuts netwerk te bevragen. Deze toestemming is geldig van maandag, 24 februari 2020 16:15:47 tot maandag, 24 februari 2020 17:15:47.",
  "timestamp": {
    "Time": 1582557442,
    "ServerUrl": "https://keyshare.privacybydesign.foundation/atumd/",
    "Sig": {
      "Alg": "ed25519",
      "Data": "+owJxphmD16dXlfpVfdRGfGnKp84RMU7ewk9lpCxV7DeQfvYgztSEVozqISLvnSz5ABNiQr1zyYOb3bths5TBw==",
      "PublicKey": "MKdXxJxEWPRIwNP7SuvP0J/M/NV51VZvqCyO+7eDwJ8="
    }
  }
}
`
const ValidIrmaContract = `
{
  "@context": "https://irma.app/ld/signature/v2",
  "signature": [
    {
      "c": "m40VOyPMjHe5KxKR/TQSWXNHM00muh0pbZFjMd14JWA=",
      "A": "W69bC6pbSJyCFPh4y9kaFpByWkR64a/FNK37pBU5IWpMPWtj3J+/eft0UR2JhF+vdZhKS+78rcYI1gALqxFoWg/FXlLzeP2S/gBHd9aTP71xhtoAzmeRA9tlrETK9rIUUDDhGTdtgJFcNzFFiSxgSveBWv8llRMxw6l/x924hlJt9o1q6snVdyBklumw3vWtG9TFWzJRZK5voCwF9t+abClxOGKX+Dn+1PLXvZCD4kPYNMzorKDcTtE5UNXbBTihOXV7VnArX2B2GTqHGU73QB3XMtDZIqg8IXoxSTL96nzwWXhn4E2RS2nQU6jO3TifoWzqymaSYQehn8JPR3Qr1A==",
      "e_response": "2PzNudT7ROCu6qPYlPtWPff1BT8NbnIBSynV1zdCH8qBkgBnPBK20iEjwsjPmIZ5NoOJyL+MEUe18sJiuppn",
      "v_response": "FZOEu8NIilVRn/gCuh4HaTmrGEjVhdHpKZg/UHuRF+ohM0QjKWVPsyVLQpJMBXBWaqLUi92iFy0ai91DJR+dkbTY8JXPb6Y878uVZ+5yvK8PULLFZ+MvkRLdD7NTICS51+usHxK1NP7r46ao7fvhWijmFoCKF7+4jFjqKn8mG7eLUeskj9v0bN6cZ4xnyC+CZ+0Dfeo/rUi8UgU2eD1F+hdjhxiYxsa8DunHEwjOdxbvtQrimsCkB8pG7ETD6Rxa7zvN67klUdCs075SxHrNDeDiU8MJJ07GEKUpaMobHpiAuHnobikSZXWS1Mj+A3IOpgSKfSZlmfV9g5k16P9rMSIdohUJiMUyhtwsBScQyyQJcRIq2qBtsTEx/9R2TGK7eqxbLgBhVknf/P6tH9CHYXGNsa2+CVihgq9B8mUALnXtrHn8mryQYYlMMFDAfjl5BdV8NDa9NjCvW/DiqH9K5VQN79KtnUAt/z/EGAFHBSEUYjL3/C2mQiXMVlwsqPkeT7JZtWLLytPi3TJ85tW8fQ==",
      "a_responses": {
        "0": "S9tt+rB2Z2tN9qd05GHkkblOMta7v9C34Qxf4lcQmrXbt+tYTr3jSrV8n3yTPM5ylFWjH+41HyVRag8i5LOsnNl+zGKbAbSVwW4=",
        "3": "6/PbsO3gfEtCCpvohvpyuKBeMIUFOQ30kveHdkd+cp1M83A2vec3QwsFvn+6Bo5uxuFafN77IPBHUATY06IYayxgi/1JXffbijhsb+5s8yw="
      },
      "a_disclosed": {
        "1": "AwAKIAAaAAFH2jklUts5iBWSlKLhMjvi",
        "2": "YGBgYGBgYG8="
      }
    }
  ],
  "indices": [
    [
      {
        "cred": 0,
        "attr": 2
      }
    ]
  ],
  "nonce": "7Y8eMnUwjkdW3eIlrcSD0Q==",
  "context": "AQ==",
  "message": "NL:BehandelaarLogin:v1 Ondergetekende geeft toestemming aan Demo EHR om namens verpleeghuis De nootjes en ondergetekende het Nuts netwerk te bevragen. Deze toestemming is geldig van dinsdag, 1 oktober 2019 13:30:42 tot dinsdag, 1 oktober 2019 14:30:42.",
  "timestamp": {
    "Time": 1569929468,
    "ServerUrl": "https://keyshare.privacybydesign.foundation/atumd/",
    "Sig": {
      "Alg": "ed25519",
      "Data": "ofaPD6qyPJi6Rfs1qUP9MZ5DT32peMa1603sTf83WVZ8IORNs16O95RuRklKnAqo2J+Tk42C8Qxd+07P8pW1Aw==",
      "PublicKey": "MKdXxJxEWPRIwNP7SuvP0J/M/NV51VZvqCyO+7eDwJ8="
    }
  }
}
`

const ForgedIrmaContract = `
{
  "@context": "https://irma.app/ld/signature/v2",
  "signature": [
    {
      "c": "m40VOyPMjHe5KxKR/TQSWXNHM00muh0pbZFjMd14JWa=",
      "A": "W69bC6pbSJyCFPh4y9kaFpByWkR64a/FNK37pBU5IWpMPWtj3J+/eft0UR2JhF+vdZhKS+78rcYI1gALqxFoWg/FXlLzeP2S/gBHd9aTP71xhtoAzmeRA9tlrETK9rIUUDDhGTdtgJFcNzFFiSxgSveBWv8llRMxw6l/x924hlJt9o1q6snVdyBklumw3vWtG9TFWzJRZK5voCwF9t+abClxOGKX+Dn+1PLXvZCD4kPYNMzorKDcTtE5UNXbBTihOXV7VnArX2B2GTqHGU73QB3XMtDZIqg8IXoxSTL96nzwWXhn4E2RS2nQU6jO3TifoWzqymaSYQehn8JPR3Qr1A==",
      "e_response": "2PzNudT7ROCu6qPYlPtWPff1BT8NbnIBSynV1zdCH8qBkgBnPBK20iEjwsjPmIZ5NoOJyL+MEUe18sJiuppn",
      "v_response": "FZOEu8NIilVRn/gCuh4HaTmrGEjVhdHpKZg/UHuRF+ohM0QjKWVPsyVLQpJMBXBWaqLUi92iFy0ai91DJR+dkbTY8JXPb6Y878uVZ+5yvK8PULLFZ+MvkRLdD7NTICS51+usHxK1NP7r46ao7fvhWijmFoCKF7+4jFjqKn8mG7eLUeskj9v0bN6cZ4xnyC+CZ+0Dfeo/rUi8UgU2eD1F+hdjhxiYxsa8DunHEwjOdxbvtQrimsCkB8pG7ETD6Rxa7zvN67klUdCs075SxHrNDeDiU8MJJ07GEKUpaMobHpiAuHnobikSZXWS1Mj+A3IOpgSKfSZlmfV9g5k16P9rMSIdohUJiMUyhtwsBScQyyQJcRIq2qBtsTEx/9R2TGK7eqxbLgBhVknf/P6tH9CHYXGNsa2+CVihgq9B8mUALnXtrHn8mryQYYlMMFDAfjl5BdV8NDa9NjCvW/DiqH9K5VQN79KtnUAt/z/EGAFHBSEUYjL3/C2mQiXMVlwsqPkeT7JZtWLLytPi3TJ85tW8fQ==",
      "a_responses": {
        "0": "S9tt+rB2Z2tN9qd05GHkkblOMta7v9C34Qxf4lcQmrXbt+tYTr3jSrV8n3yTPM5ylFWjH+41HyVRag8i5LOsnNl+zGKbAbSVwW4=",
        "3": "6/PbsO3gfEtCCpvohvpyuKBeMIUFOQ30kveHdkd+cp1M83A2vec3QwsFvn+6Bo5uxuFafN77IPBHUATY06IYayxgi/1JXffbijhsb+5s8yw="
      },
      "a_disclosed": {
        "1": "AwAKIAAaAAFH2jklUts5iBWSlKLhMjvi",
        "2": "YGBgYGBgYG8="
      }
    }
  ],
  "indices": [
    [
      {
        "cred": 0,
        "attr": 2
      }
    ]
  ],
  "nonce": "7Y8eMnUwjkdW3eIlrcSD0Q==",
  "context": "AQ==",
  "message": "NL:BehandelaarLogin:v1 Ondergetekende geeft toestemming aan Demo EHR om namens verpleeghuis De nootjes en ondergetekende het Nuts netwerk te bevragen. Deze toestemming is geldig van dinsdag, 1 oktober 2019 13:30:42 tot dinsdag, 1 oktober 2019 14:30:42.",
  "timestamp": {
    "Time": 1569929468,
    "ServerUrl": "https://keyshare.privacybydesign.foundation/atumd/",
    "Sig": {
      "Alg": "ed25519",
      "Data": "ofaPD6qyPJi6Rfs1qUP9MZ5DT32peMa1603sTf83WVZ8IORNs16O95RuRklKnAqo2J+Tk42C8Qxd+07P8pW1Aw==",
      "PublicKey": "MKdXxJxEWPRIwNP7SuvP0J/M/NV51VZvqCyO+7eDwJ8="
    }
  }
}
`

const ValidUnknownIrmaContract = `{
  "signature": [
    {
      "c": "1/7H1N1DrhKEkuD28DMPhIcX1eoq7Hhr2Spg4WggRFQ=",
      "A": "z5ywI1Form5PzkNoqPcLcVlQKhD19gZzTJtvx3nPPEVruWStQ72nTwo3hALdJdzUI301ic6M9F9B6YoLc5n1fJAvGFFGdgFir5Az6s5+3jNQMAIdSIqI1mNPrsNUcrY4hxjmBK+LpfXL3IsoPSyGw9S2gYRqjg1luI31yRWcRdFLSYIjfSY5tQAG1EE4UwqhDZGRD/iDxDD5uWk/Z0CbJM5r20Cth+VPJRMQZFy8B8irE8FiZHJMe6dDAYdzAdAPjNWbAFJ4y+7zp3k78OO4zfWCWiiJkQrXksvW3agHGHhuGZs42IrWckAnUc3FpFDpJvB8APEgMWiD/sZ0uBqi/w==",
      "e_response": "HMYVvSItEbtgnd4fIwnsiHBjpoQUdiPKcNKk4zGK0Kv5rShC4idSY4gI3l5EV+r0fBKIT6uArfyeG2Yxqp8B",
      "v_response": "Bk2GXojcbibyanT77BADGJq7OqxqVwvOIokIFCKLeGuNZ1wBzkEyRHe5Dw6IAjJag+9sEWNTQ3Kf9xDtsQ7fvnj1vOdCLmysVqY9n/nihn1qbaCXfb7gkqkwth55e52Gvd9mCDLTGPDPW/Y2fkBuSf+pidhrENOo0dWCwYnINt7HrtKd3BVVK81BzSimqSxpONb6mJeK3TNneqn0cAkLK3//3wI3AmB0NPf8UgzhNaulJKj5mEuz7Kvp/I0fYyWMNAh5rrHqi/kWoGeo7GywHIIrCAUyiZz4ozOYMh67scvsQOmCAs2Jq/vKOazIeqFASD2q6jCvnQ0zCY+VGtmV8SNwwpNeBhR6+nXTehlPZt+4x0mbme3157azfSv/ndLK14iMgfWC1gX8aOiQx/Ctx/6c5RqVFc2XqyEXVyQmUkT7AgTLrTvBq8hmqpfHY2d2kAT7ukAdp+zGDD+bpI0yMYEj8mktPDOmiRqQGeiL43ZJUbrE6YFzRqo9l3Qz8AnbzH3JlqEJnZZHXzs6/Uj30zQ=",
      "a_responses": {
        "0": "GKIQkMWEIDA3NwPkLuj1+9MEFp6licjoDiHRfbyYxrf4C3dCvEZX74ByjmirtYXZuOfpcIicHi8hPEK3ZxrLKzcJbjT+BBiTOUw=",
        "3": "HebCraFeGgQgT5TCwcq23twJSKRSWGrCTHRozyUUmaLCKDwh6rajdvwaqJ/gZLkCJFcvTPQJKb20SjQPDosgg/K/YP19R3H5MRgeUrdQgIU="
      },
      "a_disclosed": {
        "1": "AwAKCwAaAABH2jklUts5iBWSlKLhMjvi",
        "2": "YGBgYGBgYGM="
      }
    }
  ],
  "indices": [
    [
      {
        "cred": 0,
        "attr": 2
      }
    ]
  ],
  "nonce": "dz016mfjw7kITQDWHI9eFg==",
  "context": "AQ==",
  "message": "NL:PgoLogin:v1 Burger geeft aan PGO Helder toestemming om uit zijn/haar naam het Nuts netwerk te bevragen. Deze toestemming is geldig van woensdag, 1 mei 2019 16:47:52 tot woensdag, 1 mei 2019 17:47:52.",
  "timestamp": {
    "Time": 1556722159,
    "ServerUrl": "https://metrics.privacybydesign.foundation/atum",
    "Sig": {
      "Alg": "ed25519",
      "Data": "D5UUvzEkdItSiQYphP+XLv/EorpzCLrF5MYzkY4DuURYTDwldJ5/YHmT4vgbiprcgxAI+m+qQjbydCVjM/qQAw==",
      "PublicKey": "e/nMAJF7nwrvNZRpuJljNpRx+CsT7caaXyn9OX683R8="
    }
  }
} 
`
