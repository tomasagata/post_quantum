import 'dart:typed_data';

import 'package:crystals_pqc/crystals_pqc.dart';
import 'package:test/test.dart';

void main() {
  group('Kyber 512-bit tests', () {
    final kyber512 = Kyber.kem512();

    setUp(() {
      // Additional setup goes here.
    });

    test('Creating keys with given seed returns expected pre-generated keys', () {
      var seed = Uint8List.fromList([
        0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
        0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
        0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
        0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
      ]);
      var (pk, sk) = kyber512.generateKeys(seed);
      var preGeneratedPK  = r"RCG9TKs/8maxw2RDOAWjMFgrmIyFDNqY5/mVGxjMTL"
          r"jNA2E8/2Fa5XuKiiNvYFRnTKuMrXCEg2h30nstath5F0g1UGIMGwptm/UHsj"
          r"mFeaZl0LyqJNtkrOcK1qKsprqOO+SQLiEOAPl0bDLELyAH4BoPmgcVO+WvGr"
          r"nBOOHEmNhJyrPMQgm+KSSXz9OHl1ObKEtqFXkFK/NEyiQUt2SbVooGc/VTTH"
          r"U6V5I11TYY3dKqESNeiRO7RPCxsRfNQuZjOJyvdkAVFTJIndmgK5QEYONAY3"
          r"d6wturNiKzFndTvJGrV1sXDyhx4WdfydgEbJcB2ntS40B2K5M2tMdIlwRT1S"
          r"NSVStMC/NGNKNPX9M9seUgofCMHAVDHZIe/BlBeGCQ0NRExZoejVwVrrmFqO"
          r"caryQkdLhW2so/5+O0PANDUqzD7WZMoIp3C9FG0UfOBEUGHUJJqqMUgVkqN8"
          r"gpKKtJDjW9rfoW9lKEOmaut9qGN1KFVAuGT3o4Rvqhp7sMxBcMAhHFCyKV79"
          r"xSyLoAXxhu3Fe2tQkJUptmD0aUpRVcgSCS62AWQbzOvSypVmSjPoBZoLwMg2"
          r"msFumqBsY9W1OY4tK7E5Spbye3PVLOP3KSsteCrEScROKJj5BhSye5RgFqZ0"
          r"WG4LejIAoo5DkhXGUfnXeJRMyV5QSP9WOBGaMnyWMwuWMYG7AHAeKK5COQ4E"
          r"s4iveAdGOgR/YArFKVOitkm/mFeHyebDxcSfWODvKJz1opFvN0erBi9Wgar6"
          r"c3noTAECS3hQddr+Yca5ZHqAOdy1STGDleuHASMibOzkecWaNna0QIR6FkrC"
          r"w25TfDo3c0jvclXmk362g9r6rOF3lG5pmR4Lg+UnMMk6hYA7sDpitCRhSoK3"
          r"MB4HcpznHLb3cVQggMentapfls+aMJ09kTz+ZgiQIxx+FOkGWYJuCl1rQPMf"
          r"Ge93BJMcDKBqhYiAfCUCiiRVQtS7ZAJgwxzCqI+hEgMCpY6ueztWWY/gqBjP"
          r"amQ0TPudXPX7t3x/miwHWtbCB2NFXqF9RQkBPtGX5XWaAgYXe0049v6kN5nx"
          r"SVHSA=";
      var preGeneratedSK  = r"1uUWlWI3Zcpo0YBuz/tylbJS+BK5E+Z5eMyhD1pPwG"
          r"BI00KHB7fLo6w3dAA2xFqmpcjGiuphqCU1j6YFBqqvrSTJaSGdyyAM2gzL7x"
          r"WsLntxrgi7WEV6aOipC5VQDyUgKrmscYFRkpkNL2gBRycvPLgm4VzMLJagwI"
          r"q8JmLBA1i+9gWUxFS9V1IL6dBEejHKQJyVpdxOiSZdDyBXpOxFVucXZ4KYaf"
          r"kTy4mxupMYwvpddDMpjBqi+GcZzKIODVocuDI0yBwUBrk/oMxIIEUOG2asG9"
          r"UQEyJqAhkWMyRdrPgIKocYSiANnsSn/iA0PzJ0uOurR9ePxWds7Rd4F0IARg"
          r"UIyTMpBCkdzLUjIBEHBzIU00fPs5VkEGgLsKJD5CCjKWBcXVLFWGVAWyt92m"
          r"bHRSVQQsZyxUlXLTwTnfWprHwLYVqrLXmTcXFEDVOgxUSxtJxwmKF67rCDNL"
          r"BpjUZpgQR13LWQ4tW7U7lJ4XF6j9clL2w1kFhHuOuwN1FcNwgdHSxf+9E2pT"
          r"oegJNjDmCCJyh0eelYdeJLR5Ne7GAdVANEDiMsleZ/tElqr1aFxqqb7hNDMN"
          r"iHCnpuhxw/yPYHAEBheOuHHMY+L7FNA3lvKuBXquQOJbt/c3NvKfdb5chIpQ"
          r"Vn4UE6Xptb9rJ9NxVwzgQKReFq0OYnRis87lGmsYXN11Jd7OugvRFD2DqvTU"
          r"QA9tZ0G1k25GE4iMVmdbekwONSsqer5Ye20hRPUlhiSTHNXwaxn/Y+pimZ0P"
          r"g5j5wMIdoUQrXIg5VaEEaqLHWz/xQrwBBY6sqH5LZ2B3wUrhTGBgzOrUgXKy"
          r"UX1QdO6GlLoXi1BadjhPIGhuZTqPo9zHKOLaN9hDEmPKCijcMb9BkrfLKuJ4"
          r"YbibJUbpDLsFAZcPlXvgwUkWaA04G3OjcCSdJcLyoUf9F7zTZKREyMfhoFZL"
          r"tiCBR1LNQ8xqCbfXioiRtINPGQW0I5rPIrrlsok/gz9yxbrTaWP/qC+DtwAz"
          r"WMZjE1gMAw1jiVWPDIHQWZRCG9TKs/8maxw2RDOAWjMFgrmIyFDNqY5/mVGx"
          r"jMTLjNA2E8/2Fa5XuKiiNvYFRnTKuMrXCEg2h30nstath5F0g1UGIMGwptm/"
          r"UHsjmFeaZl0LyqJNtkrOcK1qKsprqOO+SQLiEOAPl0bDLELyAH4BoPmgcVO+"
          r"WvGrnBOOHEmNhJyrPMQgm+KSSXz9OHl1ObKEtqFXkFK/NEyiQUt2SbVooGc/"
          r"VTTHU6V5I11TYY3dKqESNeiRO7RPCxsRfNQuZjOJyvdkAVFTJIndmgK5QEYO"
          r"NAY3d6wturNiKzFndTvJGrV1sXDyhx4WdfydgEbJcB2ntS40B2K5M2tMdIlw"
          r"RT1SNSVStMC/NGNKNPX9M9seUgofCMHAVDHZIe/BlBeGCQ0NRExZoejVwVrr"
          r"mFqOcaryQkdLhW2so/5+O0PANDUqzD7WZMoIp3C9FG0UfOBEUGHUJJqqMUgV"
          r"kqN8gpKKtJDjW9rfoW9lKEOmaut9qGN1KFVAuGT3o4Rvqhp7sMxBcMAhHFCy"
          r"KV79xSyLoAXxhu3Fe2tQkJUptmD0aUpRVcgSCS62AWQbzOvSypVmSjPoBZoL"
          r"wMg2msFumqBsY9W1OY4tK7E5Spbye3PVLOP3KSsteCrEScROKJj5BhSye5Rg"
          r"FqZ0WG4LejIAoo5DkhXGUfnXeJRMyV5QSP9WOBGaMnyWMwuWMYG7AHAeKK5C"
          r"OQ4Es4iveAdGOgR/YArFKVOitkm/mFeHyebDxcSfWODvKJz1opFvN0erBi9W"
          r"gar6c3noTAECS3hQddr+Yca5ZHqAOdy1STGDleuHASMibOzkecWaNna0QIR6"
          r"FkrCw25TfDo3c0jvclXmk362g9r6rOF3lG5pmR4Lg+UnMMk6hYA7sDpitCRh"
          r"SoK3MB4HcpznHLb3cVQggMentapfls+aMJ09kTz+ZgiQIxx+FOkGWYJuCl1r"
          r"QPMfGe93BJMcDKBqhYiAfCUCiiRVQtS7ZAJgwxzCqI+hEgMCpY6ueztWWY/g"
          r"qBjPamQ0TPudXPX7t3x/miwHWtbCB2NFXqF9RQkBPtGX5XWaAgYXe0049v6k"
          r"N5nxSVHSDfGE51B54orGmwsTDDRX2VwcUdL/CsJNpDdH+r62MrmQABAgMEBQ"
          r"YHCAkKCwwNDg8AAQIDBAUGBwgJCgsMDQ4P";

      expect(pk.base64, preGeneratedPK);
      expect(sk.base64, preGeneratedSK);
    });
  });

  group('Kyber 768-bit tests', () {
    final kyber768 = Kyber.kem768();

    setUp(() {
      // Additional setup goes here.
    });

    test('Creating keys with given seed returns expected pre-generated keys', () {
      var seed = Uint8List.fromList([
        0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
        0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
        0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
        0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
      ]);
      var (pk, sk) = kyber768.generateKeys(seed);
      var preGeneratedPK  = r"0JOyUjiS1lA2k2U79YUGA8ViEbLLeJmKfxrAA6ALvZ"
          r"mQLZNXHoCi2BVeDTRl6JMQOqRUC4rGAjh71nKccBwMeeKWeFMrwkQW9ziBuk"
          r"wRyvG0feMTVsVscIEXRCmlCRRqQ+VqsxapItEElbgvHXKtZpY7PaOsBXtavC"
          r"dTYNl+7HiEIkA8BweOKNpjlQN4FHtmp2zGToddjKtpU8l9a7upCEAJ1Yqf+t"
          r"u3kRRdF8Bgmvc6fKYrv2ue7PYjbhfJflAfe6fCoNM/hDTGBrN644WQ2VEtaN"
          r"RTIuhHOHNDwPlNYaU3DVEubPjP/NRjodJrUSUxUmOpyKY8z5dXriZ50uEvff"
          r"UFWSAycKu1YAg+rxElsNqAb3u+1CWlF7VwKUZR3jGlT9o9i8KtY5YY8uK1oq"
          r"CD2LpdfVIRjJEDYuAqoBmd45AFW2o5yCMJRNlg1XfJnXWhYgJehrmxgHKYRT"
          r"MiyXO1kowIeUYEWcCDtbZMTTISDRxpFaIOK5tCOKpmTJqNTAMGPpSvMHgv7f"
          r"cXqAtsgIfGWICbkCtK4VKAlZI08ZERppluMuIj4zx2D3tG07Sd4dpEqHYi2h"
          r"JCdzEvxhmdG4mGexxa7yCwiyYoQcoeFrGeibZdmqMSrRkjJkEiKHk8bABL+G"
          r"W9A6yYX7mi+TRS+IYjIXG+ASV7QWNqy4FNQDp0SveaeoRoWSVMyizE80qki3"
          r"FXlMCyV0VCDweVc1apoaxv96kLuTINKHykgEdLghi5idOPopM/LiZbLQU8p5"
          r"Mli6iknqh+uYZXaiRaJsh2kFdaKjZJtInGNXuUc0QFrNVF5gQi+bR6K/Uu0w"
          r"yrHMswvAA9HcZn0HepgPfOGIo4MjglYQq8uui2taVoOJOOfhBk69lxZay6UA"
          r"AP2cxS3PCXT1fINroBAumSQ9IIiSJp7UlbCRnJCWl3e+B8rRvAY9sF0GY+1E"
          r"OIu4uRStBaEdA0mBYHUHPOyFMFBwtbWfWGkmc0hQyl+bya/mSv1gGgvlc0cX"
          r"ptOguXrGEuPBC8cYQy7IYwrYN5myTLmlArC9p0m6HJNzmR6SwXbnM3DOp2Lk"
          r"k0bBwy8fqtqnEDoWgJAFeLhHQ1WsQhx6o/xGYTVGhW1TU46DKVA1ugO7ekdc"
          r"FrsJaCcESl4WSDjcFTqsyP4tq0xBSuHYZf4xadWbltsuzJQuylktiC+rMlnr"
          r"ZJ3yA+LqMixpSs1EsXPLp64RadWcIPIQY3liWgkoi/4FodKDsAwuDChNFLdx"
          r"VKJDhvbpJdaeF+v+FaNxVhjlNNPSSVVxDMlrow07aqlZAhSAMsUuwdGwMREl"
          r"Nb/rh10sEH7QQvNroi5As3wNCzd9soBVl5BTyJYCAM+AMhmnxUBCXGGRVmpr"
          r"C8x3MTnNsKtXaS+YJrfsaKgHczkwB08dOXI9mc4NC3oug1RyQvZKGJaWdn/N"
          r"qLJ/RnNXlJUDyeZYDLZuxU8LeCoWtT0SFbEVszEuw/PrhV21hwU9V9wzRQ4K"
          r"uc41YMjwdgLSFDCBFX9BGdMgU/xKUoJ6GmPLcElIimYdbHSbSLP8B8bCB2NF"
          r"XqF9RQkBPtGX5XWaAgYXe0049v6kN5nxSVHSA=";

      var preGeneratedSK  = r"c4AngGlOVaatQqd2FGcQ+pc/fZCYsNup4NeeFgCcEc"
          r"NIlscUVjVr+kKtGnRZ4VO/OVqf/9c3oaAj+YsuxtRW40zLbfWSWalsrpt2s8"
          r"N2eHEBMaQM3ue4u1KuVvc2J9zEa4OKOfFMG5lpLek+tva9TNUPQ4KY+ZDJJX"
          r"Q7DvcgZaKPw1upwudxV1FgQNqx54sQJDuvMqjH/GSMIGhVYCWHjrakbuibEK"
          r"OZMGWkg6cLRFQcs6q1DKh3SsS4s7CVHOlj1WLAMrfFloMbOchsC3Mjotoie4"
          r"JbKSNV+oGpqROd+OkIt3RsIREqXgseWVJ8SclUNnw+c1hhhzRmycdMJsXBWa"
          r"g4z3QUdZUPjxhVqLVQe3ZUdFuRj2J5hYZQ06CblZtWY2d5oiXB6pgemTWJ/z"
          r"w6l7N77up1+EAw7tGJRVE2ojyBnNegz+iEm+VLG8hczxWe0TpAg/h1nFq6GR"
          r"QXaFzI0CF6eSSDAFJzYal9yzyEI7B/94VCTXQWSIg6zyxCmpcv5GA/l5ROYM"
          r"YTcUd/rMJUEjSq2nExjhmYRVsXrzgOh3lZbhs1WZkFGeuohsOkQGnPmojNrh"
          r"Jk8oRcLUF+NFahNVypM7FQ0yCL5dOP/BK3/aZj44e+Uvt5XkB4w/m4kVqcwu"
          r"mSc7E0QfoQW4aommk1w+Cvt6HFH6hwexpzl7a7XrVjDQPCC0Zb4ZRpnEdKVT"
          r"ZoJUAIJ5h24WtEraUofeYfEsSvO2amSovFt6JH2kSrJFGqIAfDr2UXrEd9nN"
          r"o+FvEP/BcQFTCmhwdsbXaw8IekDVMVS1p549ohxido2alC/ypoj9uU81OVfA"
          r"wEWpJmu4cL46ZiG8zFykMYHvxHx2iNcosX7uugkaynkbC3TNmbtIwwbIOksl"
          r"FRo/W3FLEXqPto24LEREdF86GNabQ2DjQytAgHsDg1rdEhS4ep3cBXivN3In"
          r"CIIHqqqOCuZJxOXccGdlPIVSoxDpIqqOc/obgatUYhX1KGJCW4LKRJIrtDxQ"
          r"YOu8tM4/ebXdKfivufbnWCDWiNzsO6oBYy2HEO7Vu8ivGEWfC1heU9v+clFy"
          r"uciVloghJaQvsuZkAbBtOqjYGjeSMTF3Ka4LuPHea6IAdXRds9c0VERciDsp"
          r"CsMNIty0QUb0t3OdnB0ilD4MUDJGs7QTGjaJVnjPi4MVUPF4SE+XUGC/CLa0"
          r"RyR8ohAZh231kT6KSkClwBZFtB3tM+qDBvqczCEPOK3QGZ38GztJagQZuUi1"
          r"vAFEytd9tsiavHK+PMGxojnho4UiC1+QvCQgwfF3tjd3Q/lRAMPAa6mbwZf5"
          r"V/jnNXXZo7XWOgeUE3cwqL7SKpRKIETmg9d6WI8iAOSHdkKFJ5UsCdjWzFpT"
          r"SwFFQRi9EGl1cTCSIq6pojIfNlUhANZRZfkmA+UZhXGAXH3vOtyEggLwwjzI"
          r"DNdXVFwydgn+owa3Iw6+aeanIeEbMHfBiL3muY69uFonQFiam4Max4fIUbgO"
          r"yESpRSmAgRqBosqqCe6Uy+F/y2G0l+rQfFlbgzJwmp4wIRQsuZ+PAJ0JOyUj"
          r"iS1lA2k2U79YUGA8ViEbLLeJmKfxrAA6ALvZmQLZNXHoCi2BVeDTRl6JMQOq"
          r"RUC4rGAjh71nKccBwMeeKWeFMrwkQW9ziBukwRyvG0feMTVsVscIEXRCmlCR"
          r"RqQ+VqsxapItEElbgvHXKtZpY7PaOsBXtavCdTYNl+7HiEIkA8BweOKNpjlQ"
          r"N4FHtmp2zGToddjKtpU8l9a7upCEAJ1Yqf+tu3kRRdF8Bgmvc6fKYrv2ue7P"
          r"YjbhfJflAfe6fCoNM/hDTGBrN644WQ2VEtaNRTIuhHOHNDwPlNYaU3DVEubP"
          r"jP/NRjodJrUSUxUmOpyKY8z5dXriZ50uEvffUFWSAycKu1YAg+rxElsNqAb3"
          r"u+1CWlF7VwKUZR3jGlT9o9i8KtY5YY8uK1oqCD2LpdfVIRjJEDYuAqoBmd45"
          r"AFW2o5yCMJRNlg1XfJnXWhYgJehrmxgHKYRTMiyXO1kowIeUYEWcCDtbZMTT"
          r"ISDRxpFaIOK5tCOKpmTJqNTAMGPpSvMHgv7fcXqAtsgIfGWICbkCtK4VKAlZ"
          r"I08ZERppluMuIj4zx2D3tG07Sd4dpEqHYi2hJCdzEvxhmdG4mGexxa7yCwiy"
          r"YoQcoeFrGeibZdmqMSrRkjJkEiKHk8bABL+GW9A6yYX7mi+TRS+IYjIXG+AS"
          r"V7QWNqy4FNQDp0SveaeoRoWSVMyizE80qki3FXlMCyV0VCDweVc1apoaxv96"
          r"kLuTINKHykgEdLghi5idOPopM/LiZbLQU8p5Mli6iknqh+uYZXaiRaJsh2kF"
          r"daKjZJtInGNXuUc0QFrNVF5gQi+bR6K/Uu0wyrHMswvAA9HcZn0HepgPfOGI"
          r"o4MjglYQq8uui2taVoOJOOfhBk69lxZay6UAAP2cxS3PCXT1fINroBAumSQ9"
          r"IIiSJp7UlbCRnJCWl3e+B8rRvAY9sF0GY+1EOIu4uRStBaEdA0mBYHUHPOyF"
          r"MFBwtbWfWGkmc0hQyl+bya/mSv1gGgvlc0cXptOguXrGEuPBC8cYQy7IYwrY"
          r"N5myTLmlArC9p0m6HJNzmR6SwXbnM3DOp2Lkk0bBwy8fqtqnEDoWgJAFeLhH"
          r"Q1WsQhx6o/xGYTVGhW1TU46DKVA1ugO7ekdcFrsJaCcESl4WSDjcFTqsyP4t"
          r"q0xBSuHYZf4xadWbltsuzJQuylktiC+rMlnrZJ3yA+LqMixpSs1EsXPLp64R"
          r"adWcIPIQY3liWgkoi/4FodKDsAwuDChNFLdxVKJDhvbpJdaeF+v+FaNxVhjl"
          r"NNPSSVVxDMlrow07aqlZAhSAMsUuwdGwMRElNb/rh10sEH7QQvNroi5As3wN"
          r"Czd9soBVl5BTyJYCAM+AMhmnxUBCXGGRVmprC8x3MTnNsKtXaS+YJrfsaKgH"
          r"czkwB08dOXI9mc4NC3oug1RyQvZKGJaWdn/NqLJ/RnNXlJUDyeZYDLZuxU8L"
          r"eCoWtT0SFbEVszEuw/PrhV21hwU9V9wzRQ4Kuc41YMjwdgLSFDCBFX9BGdMg"
          r"U/xKUoJ6GmPLcElIimYdbHSbSLP8B8bCB2NFXqF9RQkBPtGX5XWaAgYXe004"
          r"9v6kN5nxSVHSC+doj2o+F7PE67eOsPT7yPhqSfltQXv7alWVZNmIEnDwABAg"
          r"MEBQYHCAkKCwwNDg8AAQIDBAUGBwgJCgsMDQ4P";

      expect(pk.base64, preGeneratedPK);
      expect(sk.base64, preGeneratedSK);
    });
  });

  group('Kyber 1024-bit tests', () {
    final kyber1024 = Kyber.kem1024();

    setUp(() {
      // Additional setup goes here.
    });

    test('Creating keys with given seed returns expected pre-generated keys', () {
      var seed = Uint8List.fromList([
        0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
        0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
        0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
        0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
      ]);
      var (pk, sk) = kyber1024.generateKeys(seed);
      var preGeneratedPK  = r"DXlNtoypKpKXyvwmDANI4kYQAnGAIqR2IOuNkcu6kD"
          r"atvKBFA8aagvJQS6yf/QV9bdq9qYew0oFjmfQ1UdMKhKmC+7wOfaUXhBwxbX"
          r"gRGDt4gyx6DXCyWfxROTOWqtRIPBZ9HJcm4rJOpaaXD2xGSRdd7XQ8gDBXeQ"
          r"U725jA3FM4/tmsXJBmw4uf04hXEyqEF0ukryUEoQhHH5CgVFE5aGtSk7HGT0"
          r"iWq4NcbTW12YK5ECVst9W1plSMD5ckyqVw1+EazYN64mCnTGaYLJSpv5lTRO"
          r"gpMVotuDMdAOw5AhFKe2KEcalfazEFCciGEFaZhzN2kFnJVmkkTVaqbtBCu+"
          r"hNsYG+2nLFYBlqf5iMj5KMQpm8YTQDTlSZjKS99lUbpgKsRzazcpEOEUt0RN"
          r"Z21/mPcoKDaIOKdkm6uAoC17fApOlRxSE03FI9lDIB6jkE43w/zqUEsxEC99"
          r"UOmCOxDKUJlpPI/RWSU/ugClQF0razBbCauIlXf9o1Q8TGYZMXhasBR3VQSn"
          r"pTAng2NTppBBFc1lIvRIOXTIrFu5cAmbgQXtBqZVWluGBeETQS5kZtcBYzBR"
          r"IKpQlotiRlMdWUtChBMCwAFBZ/wDpwTiOppyRDYRJO/fmP4XoDm8F3RXs1ez"
          r"y//WyRTQRG7yMmjBYRfDUnQiwX4YCYqLBvEwOaswynhHA+Jnms/5gBp6kJa/"
          r"nBaGM7/lOZsmdXsWk0XkY88qizjYQ+XokYU6MF+cpV6yODM7KnmvRbm5Vy8k"
          r"GVCeUWfVBZUPtsqOHNLajIhIcQ7mQrvcul6UqYmJN8XbABjROwphpFQ7yOmx"
          r"Wd2OYbmsjII9iWd4hnPRuhXqAVLichgaM4vrgdyQwY2HEsQAggRIgqtFhVwh"
          r"SWjqesgpGjlxu3P2mmFyKjV6YyQnM27yi5VRnJHsDNaKm4GAR2cguKndBJ2J"
          r"M+5oUCvLUTf1aItcKhZwFFTzsLl6NIH+y2r9zL3eV1FRhdDWKE1EtjQKUEzm"
          r"ulKRpnkdUmh5YhRpVbU/ND64ozK6tuKNpYYQR+SXyoq7YA5Os4K9zA2JtUbt"
          r"tuG3h7pMyHxCtONjCMOlq5O+XCHuevSPArOZyKiRUSjCCnuDlGqMQ74Oi1rQ"
          r"TAlmlyfhol/4dU+8qC+NYbVbkC4HBenSyKFQxN47gjOCcFGlu+lcoIOIuyxU"
          r"c++Jl7i5g0C3c69cM503ybTGg0tpgdV9kHJDSRtygVxLSRresBMiiDUMUCRm"
          r"Ba1sxZ4JOcswOoakyqQzeAiMZWZguvhhilHXgTa0dqfwOlL5xB3zxHrjiwGU"
          r"tHFBUMtUWOKhGDnCkRzINj0kFY3oE4dQd6mDOjvpBwRNN9zWdF7FhgjPALXM"
          r"dnWSaUXYWOCzMKZpJAIGmApghlOyKaVHtNq0dBLtQ/FPeleWK45ltm3GEu4b"
          r"mIWGwRVwmDAnc+6sjBisEQd/QWgWUBOXhMT5EnbKlzsYYyqhkHbOrDF7kJFP"
          r"YvP3S60WQA7Ps05oJv/cdNNaIHfkvBt4W1yvSi41MwC5R0PakJsOypeuV39S"
          r"EN86LLaoWJvNW6hnk4e2VQhJyii9CmR/aM6eo8wndcoPvPWMNoyCQfgwCuis"
          r"yGrNcBASnGDQUyLsVTREIFulZSwUlxA2FpZmtWbmIC4QK0kqdoBOccHKFHXL"
          r"oZXdyTKAKk6Cu+0JdH1ccOwqu6b8SLveFtZWyVQdShV/aV0qWhGVxrYZo/kP"
          r"VJb0yAoGqwtFhqZjpcIbQ7qIV5m8ODzZgLyXdW84cf/LiiGvmhMdUcOHGN15"
          r"I5zotmrgUwWlKt4STGccpmijJtBBzDIjAw/jRIJwbOCHor+QIsB+mIdoSWiA"
          r"x/xoTOWFGUkHwY4tRfZxxD94ONjvRTtTikFhSq/3mtzcexSnmeMAUBX9RgwF"
          r"d5NEo1mehA61s5wViyqRaECVAGwJMkRFNmWXhCYIcU7iwWyWi61gwa6vY783"
          r"GirICZF5uPoyp5hOZ58hJW/IWQfyl56dxY5HAmfudOIBpuFnGdgkmpIiYVfm"
          r"uBc0OIPAmkXAkmLkNdOHQoT7k2bCB2NFXqF9RQkBPtGX5XWaAgYXe0049v6k"
          r"N5nxSVHSA=";

      var preGeneratedSK  = r"c4AngGlOVaatQqd2FGcQ+pc/fZCYsNup4NeeFgCcEc"
          r"NIlscUVjVr+kKtGnRZ4VO/OVqf/9c3oaAj+YsuxtRW40zLbfWSWalsrpt2s8"
          r"N2eHEBMaQM3ue4u1KuVvc2J9zEa4OKOfFMG5lpLek+tva9TNUPQ4KY+ZDJJX"
          r"Q7DvcgZaKPw1upwudxV1FgQNqx54sQJDuvMqjH/GSMIGhVYCWHjrakbuibEK"
          r"OZMGWkg6cLRFQcs6q1DKh3SsS4s7CVHOlj1WLAMrfFloMbOchsC3Mjotoie4"
          r"JbKSNV+oGpqROd+OkIt3RsIREqXgseWVJ8SclUNnw+c1hhhzRmycdMJsXBWa"
          r"g4z3QUdZUPjxhVqLVQe3ZUdFuRj2J5hYZQ06CblZtWY2d5oiXB6pgemTWJ/z"
          r"w6l7N77up1+EAw7tGJRVE2ojyBnNegz+iEm+VLG8hczxWe0TpAg/h1nFq6GR"
          r"QXaFzI0CF6eSSDAFJzYal9yzyEI7B/94VCTXQWSIg6zyxCmpcv5GA/l5ROYM"
          r"YTcUd/rMJUEjSq2nExjhmYRVsXrzgOh3lZbhs1WZkFGeuohsOkQGnPmojNrh"
          r"Jk8oRcLUF+NFahNVypM7FQ0yCL5dOP/BK3/aZj44e+Uvt5XkB4w/m4kVqcwu"
          r"mSc7E0QfoQW4aommk1w+Cvt6HFH6hwexpzl7a7XrVjDQPCC0Zb4ZRpnEdKVT"
          r"ZoJUAIJ5h24WtEraUofeYfEsSvO2amSovFt6JH2kSrJFGqIAfDr2UXrEd9nN"
          r"o+FvEP/BcQFTCmhwdsbXaw8IekDVMVS1p549ohxido2alC/ypoj9uU81OVfA"
          r"wEWpJmu4cL46ZiG8zFykMYHvxHx2iNcosX7uugkaynkbC3TNmbtIwwbIOksl"
          r"FRo/W3FLEXqPto24LEREdF86GNabQ2DjQytAgHsDg1rdEhS4ep3cBXivN3In"
          r"CIIHqqqOCuZJxOXccGdlPIVSoxDpIqqOc/obgatUYhX1KGJCW4LKRJIrtDxQ"
          r"YOu8tM4/ebXdKfivufbnWCDWiNzsO6oBYy2HEO7Vu8ivGEWfC1heU9v+clFy"
          r"uciVloghJaQvsuZkAbBtOqjYGjeSMTF3Ka4LuPHea6IAdXRds9c0VERciDsp"
          r"CsMNIty0QUb0t3OdnB0ilD4MUDJGs7QTGjaJVnjPi4MVUPF4SE+XUGC/CLa0"
          r"RyR8ohAZh231kT6KSkClwBZFtB3tM+qDBvqczCEPOK3QGZ38GztJagQZuUi1"
          r"vAFEytd9tsiavHK+PMGxojnho4UiC1+QvCQgwfF3tjd3Q/lRAMPAa6mbwZf5"
          r"V/jnNXXZo7XWOgeUE3cwqL7SKpRKIETmg9d6WI8iAOSHdkKFJ5UsCdjWzFpT"
          r"SwFFQRi9EGl1cTCSIq6pojIfNlUhANZRZfkmA+UZhXGAXH3vOtyEggLwwjzI"
          r"DNdXVFwydgn+owa3Iw6+aeanIeEbMHfBiL3muY69uFonQFiam4Max4fIUbgO"
          r"yESpRSmAgRqBosqqCe6Uy+F/y2G0l+rQfFlbgzJwmp4wIRQsuZ+PAJkjxcYE"
          r"qoZQkcIdBQTqIW28cjyLAZcNi8Qay9iXS63cU8UmNeoDQJpQE0fBGd5Zg+DZ"
          r"yOuWGKxHcZsHET3QyJRGyLcuCtO2KW+5BvtrRF4tAdFvjDTalg41y7PhyqSO"
          r"Ou1nI+hvUVsnZUXoou3kWWeswy/hyyQJKGS+Al13K92VY/pGwGZKZgzoM80u"
          r"YxfRgYBGqCQdwX0yWUdwQFQzw2Z/W5Nbe2b+dWi1DI+Yc1FaOiNAim4JZQeY"
          r"bNkjhaKccy1CZNk9lNqFkCc2m2haF/uao2anwhi7wsXhsRagmR9QlB2DJ+f5"
          r"Eoetc569V3cJWmUzND8TgK6AC/L+cdO+rMPbZvdKVc7be+UaySWoWnYburTL"
          r"QyzYs0VqZArXdGMNCfr+qfm2oF4gtJPLAIgKccIxR/hHM0TWgT+YPPveNqKc"
          r"y+Y6IBNQVVi4HLkvyuXQYNdiWs/5acY0xgKMG2sLgqURCPbipPQ3cX0gzQ1O"
          r"KKeItAA6sm6pAOpHDEQpg16skDDXlNtoypKpKXyvwmDANI4kYQAnGAIqR2IO"
          r"uNkcu6kDatvKBFA8aagvJQS6yf/QV9bdq9qYew0oFjmfQ1UdMKhKmC+7wOfa"
          r"UXhBwxbXgRGDt4gyx6DXCyWfxROTOWqtRIPBZ9HJcm4rJOpaaXD2xGSRdd7X"
          r"Q8gDBXeQU725jA3FM4/tmsXJBmw4uf04hXEyqEF0ukryUEoQhHH5CgVFE5aG"
          r"tSk7HGT0iWq4NcbTW12YK5ECVst9W1plSMD5ckyqVw1+EazYN64mCnTGaYLJ"
          r"Spv5lTROgpMVotuDMdAOw5AhFKe2KEcalfazEFCciGEFaZhzN2kFnJVmkkTV"
          r"aqbtBCu+hNsYG+2nLFYBlqf5iMj5KMQpm8YTQDTlSZjKS99lUbpgKsRzazcp"
          r"EOEUt0RNZ21/mPcoKDaIOKdkm6uAoC17fApOlRxSE03FI9lDIB6jkE43w/zq"
          r"UEsxEC99UOmCOxDKUJlpPI/RWSU/ugClQF0razBbCauIlXf9o1Q8TGYZMXha"
          r"sBR3VQSnpTAng2NTppBBFc1lIvRIOXTIrFu5cAmbgQXtBqZVWluGBeETQS5k"
          r"ZtcBYzBRIKpQlotiRlMdWUtChBMCwAFBZ/wDpwTiOppyRDYRJO/fmP4XoDm8"
          r"F3RXs1ezy//WyRTQRG7yMmjBYRfDUnQiwX4YCYqLBvEwOaswynhHA+Jnms/5"
          r"gBp6kJa/nBaGM7/lOZsmdXsWk0XkY88qizjYQ+XokYU6MF+cpV6yODM7Knmv"
          r"Rbm5Vy8kGVCeUWfVBZUPtsqOHNLajIhIcQ7mQrvcul6UqYmJN8XbABjROwph"
          r"pFQ7yOmxWd2OYbmsjII9iWd4hnPRuhXqAVLichgaM4vrgdyQwY2HEsQAggRI"
          r"gqtFhVwhSWjqesgpGjlxu3P2mmFyKjV6YyQnM27yi5VRnJHsDNaKm4GAR2cg"
          r"uKndBJ2JM+5oUCvLUTf1aItcKhZwFFTzsLl6NIH+y2r9zL3eV1FRhdDWKE1E"
          r"tjQKUEzmulKRpnkdUmh5YhRpVbU/ND64ozK6tuKNpYYQR+SXyoq7YA5Os4K9"
          r"zA2JtUbttuG3h7pMyHxCtONjCMOlq5O+XCHuevSPArOZyKiRUSjCCnuDlGqM"
          r"Q74Oi1rQTAlmlyfhol/4dU+8qC+NYbVbkC4HBenSyKFQxN47gjOCcFGlu+lc"
          r"oIOIuyxUc++Jl7i5g0C3c69cM503ybTGg0tpgdV9kHJDSRtygVxLSRresBMi"
          r"iDUMUCRmBa1sxZ4JOcswOoakyqQzeAiMZWZguvhhilHXgTa0dqfwOlL5xB3z"
          r"xHrjiwGUtHFBUMtUWOKhGDnCkRzINj0kFY3oE4dQd6mDOjvpBwRNN9zWdF7F"
          r"hgjPALXMdnWSaUXYWOCzMKZpJAIGmApghlOyKaVHtNq0dBLtQ/FPeleWK45l"
          r"tm3GEu4bmIWGwRVwmDAnc+6sjBisEQd/QWgWUBOXhMT5EnbKlzsYYyqhkHbO"
          r"rDF7kJFPYvP3S60WQA7Ps05oJv/cdNNaIHfkvBt4W1yvSi41MwC5R0PakJsO"
          r"ypeuV39SEN86LLaoWJvNW6hnk4e2VQhJyii9CmR/aM6eo8wndcoPvPWMNoyC"
          r"QfgwCuisyGrNcBASnGDQUyLsVTREIFulZSwUlxA2FpZmtWbmIC4QK0kqdoBO"
          r"ccHKFHXLoZXdyTKAKk6Cu+0JdH1ccOwqu6b8SLveFtZWyVQdShV/aV0qWhGV"
          r"xrYZo/kPVJb0yAoGqwtFhqZjpcIbQ7qIV5m8ODzZgLyXdW84cf/LiiGvmhMd"
          r"UcOHGN15I5zotmrgUwWlKt4STGccpmijJtBBzDIjAw/jRIJwbOCHor+QIsB+"
          r"mIdoSWiAx/xoTOWFGUkHwY4tRfZxxD94ONjvRTtTikFhSq/3mtzcexSnmeMA"
          r"UBX9RgwFd5NEo1mehA61s5wViyqRaECVAGwJMkRFNmWXhCYIcU7iwWyWi61g"
          r"wa6vY783GirICZF5uPoyp5hOZ58hJW/IWQfyl56dxY5HAmfudOIBpuFnGdgk"
          r"mpIiYVfmuBc0OIPAmkXAkmLkNdOHQoT7k2bCB2NFXqF9RQkBPtGX5XWaAgYX"
          r"e0049v6kN5nxSVHSBYk8uJp78dSNH93nrvqRW3TFy8+cb0Y4stipaZjOfvvA"
          r"ABAgMEBQYHCAkKCwwNDg8AAQIDBAUGBwgJCgsMDQ4P";

      expect(pk.base64, preGeneratedPK);
      expect(sk.base64, preGeneratedSK);
    });
  });
}
