import mimetypes
import pathlib

mime_data = {}
mime_data[".323"] = "text/h323"
mime_data[".3g2"] = "video/3gpp2"
mime_data[".3gp2"] = "video/3gpp2"
mime_data[".3gp"] = "video/3gpp"
mime_data[".3gpp"] = "video/3gpp"
mime_data[".aaf"] = "application/octet-stream"
mime_data[".aac"] = "audio/aac"
mime_data[".aca"] = "application/octet-stream"
mime_data[".accdb"] = "application/msaccess"
mime_data[".accde"] = "application/msaccess"
mime_data[".accdt"] = "application/msaccess"
mime_data[".acx"] = "application/internet-property-stream"
mime_data[".adt"] = "audio/vnd.dlna.adts"
mime_data[".adts"] = "audio/vnd.dlna.adts"
mime_data[".afm"] = "application/octet-stream"
mime_data[".ai"] = "application/postscript"
mime_data[".aif"] = "audio/x-aiff"
mime_data[".aifc"] = "audio/aiff"
mime_data[".aiff"] = "audio/aiff"
mime_data[".application"] = "application/x-ms-application"
mime_data[".art"] = "image/x-jg"
mime_data[".asd"] = "application/octet-stream"
mime_data[".asf"] = "video/x-ms-asf"
mime_data[".asi"] = "application/octet-stream"
mime_data[".asm"] = "text/plain"
mime_data[".asr"] = "video/x-ms-asf"
mime_data[".asx"] = "video/x-ms-asf"
mime_data[".atom"] = "application/atom+xml"
mime_data[".au"] = "audio/basic"
mime_data[".avi"] = "video/avi"
mime_data[".axs"] = "application/olescript"
mime_data[".bas"] = "text/plain"
mime_data[".bcpio"] = "application/x-bcpio"
mime_data[".bin"] = "application/octet-stream"
mime_data[".bmp"] = "image/bmp"
mime_data[".c"] = "text/plain"
mime_data[".cab"] = "application/vnd.ms-cab-compressed"
mime_data[".calx"] = "application/vnd.ms-office.calx"
mime_data[".cat"] = "application/vnd.ms-pki.seccat"
mime_data[".cdf"] = "application/x-cdf"
mime_data[".chm"] = "application/octet-stream"
mime_data[".class"] = "application/x-java-applet"
mime_data[".clp"] = "application/x-msclip"
mime_data[".cmx"] = "image/x-cmx"
mime_data[".cnf"] = "text/plain"
mime_data[".cod"] = "image/cis-cod"
mime_data[".cpio"] = "application/x-cpio"
mime_data[".cpp"] = "text/plain"
mime_data[".crd"] = "application/x-mscardfile"
mime_data[".crl"] = "application/pkix-crl"
mime_data[".crt"] = "application/x-x509-ca-cert"
mime_data[".csh"] = "application/x-csh"
mime_data[".css"] = "text/css"
mime_data[".csv"] = "application/octet-stream"
mime_data[".cur"] = "application/octet-stream"
mime_data[".dcr"] = "application/x-director"
mime_data[".deploy"] = "application/octet-stream"
mime_data[".der"] = "application/x-x509-ca-cert"
mime_data[".dib"] = "image/bmp"
mime_data[".dir"] = "application/x-director"
mime_data[".disco"] = "text/xml"
mime_data[".dll"] = "application/x-msdownload"
mime_data[".dll.configuration"] = "text/xml"
mime_data[".dlm"] = "text/dlm"
mime_data[".doc"] = "application/msword"
mime_data[".docm"] = "application/vnd.ms-word.document.macroEnabled.12"
mime_data[".docx"] = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
mime_data[".dot"] = "application/msword"
mime_data[".dotm"] = "application/vnd.ms-word.template.macroEnabled.12"
mime_data[".dotx"] = "application/vnd.openxmlformats-officedocument.wordprocessingml.template"
mime_data[".dsp"] = "application/octet-stream"
mime_data[".dtd"] = "text/xml"
mime_data[".dvi"] = "application/x-dvi"
mime_data[".dvr-ms"] = "video/x-ms-dvr"
mime_data[".dwf"] = "drawing/x-dwf"
mime_data[".dwp"] = "application/octet-stream"
mime_data[".dxr"] = "application/x-director"
mime_data[".eml"] = "message/rfc822"
mime_data[".emz"] = "application/octet-stream"
mime_data[".eot"] = "application/vnd.ms-fontobject"
mime_data[".eps"] = "application/postscript"
mime_data[".etx"] = "text/x-setext"
mime_data[".evy"] = "application/envoy"
mime_data[".exe"] = "application/octet-stream"
mime_data[".exe.configuration"] = "text/xml"
mime_data[".fdf"] = "application/vnd.fdf"
mime_data[".fif"] = "application/fractals"
mime_data[".fla"] = "application/octet-stream"
mime_data[".flr"] = "x-world/x-vrml"
mime_data[".flv"] = "video/x-flv"
mime_data[".gif"] = "image/gif"
mime_data[".gtar"] = "application/x-gtar"
mime_data[".gz"] = "application/x-gzip"
mime_data[".h"] = "text/plain"
mime_data[".hdf"] = "application/x-hdf"
mime_data[".hdml"] = "text/x-hdml"
mime_data[".hhc"] = "application/x-oleobject"
mime_data[".hhk"] = "application/octet-stream"
mime_data[".hhp"] = "application/octet-stream"
mime_data[".hlp"] = "application/winhlp"
mime_data[".hqx"] = "application/mac-binhex40"
mime_data[".hta"] = "application/hta"
mime_data[".htc"] = "text/x-component"
mime_data[".htm"] = "text/html"
mime_data[".html"] = "text/html"
mime_data[".htt"] = "text/webviewhtml"
mime_data[".hxt"] = "text/html"
mime_data[".ico"] = "image/x-icon"
mime_data[".ics"] = "text/calendar"
mime_data[".ief"] = "image/ief"
mime_data[".iii"] = "application/x-iphone"
mime_data[".inf"] = "application/octet-stream"
mime_data[".ins"] = "application/x-internet-signup"
mime_data[".isp"] = "application/x-internet-signup"
mime_data[".IVF"] = "video/x-ivf"
mime_data[".jar"] = "application/java-archive"
mime_data[".java"] = "application/octet-stream"
mime_data[".jck"] = "application/liquidmotion"
mime_data[".jcz"] = "application/liquidmotion"
mime_data[".jfif"] = "image/pjpeg"
mime_data[".jpb"] = "application/octet-stream"
mime_data[".jpe"] = "image/jpeg"
mime_data[".jpeg"] = "image/jpeg"
mime_data[".jpg"] = "image/jpeg"
mime_data[".js"] = "application/javascript"
mime_data[".json"] = "application/json"
mime_data[".jsx"] = "application/javascrip"
mime_data[".latex"] = "application/x-latex"
mime_data[".lit"] = "application/x-ms-reader"
mime_data[".lpk"] = "application/octet-stream"
mime_data[".lsf"] = "video/x-la-asf"
mime_data[".lsx"] = "video/x-la-asf"
mime_data[".lzh"] = "application/octet-stream"
mime_data[".m13"] = "application/x-msmediaview"
mime_data[".m14"] = "application/x-msmediaview"
mime_data[".m1v"] = "video/mpeg"
mime_data[".m2ts"] = "video/vnd.dlna.mpeg-tts"
mime_data[".m3u"] = "audio/x-mpegurl"
mime_data[".m4a"] = "audio/mp4"
mime_data[".m4v"] = "video/mp4"
mime_data[".man"] = "application/x-troff-man"
mime_data[".manifest"] = "application/x-ms-manifest"
mime_data[".map"] = "text/plain"
mime_data[".mdb"] = "application/x-msaccess"
mime_data[".mdp"] = "application/octet-stream"
mime_data[".me"] = "application/x-troff-me"
mime_data[".mht"] = "message/rfc822"
mime_data[".mhtml"] = "message/rfc822"
mime_data[".mid"] = "audio/mid"
mime_data[".midi"] = "audio/mid"
mime_data[".mix"] = "application/octet-stream"
mime_data[".mmf"] = "application/x-smaf"
mime_data[".mno"] = "text/xml"
mime_data[".mny"] = "application/x-msmoney"
mime_data[".mov"] = "video/quicktime"
mime_data[".movie"] = "video/x-sgi-movie"
mime_data[".mp2"] = "video/mpeg"
mime_data[".mp3"] = "audio/mpeg"
mime_data[".mp4"] = "video/mp4"
mime_data[".mp4v"] = "video/mp4"
mime_data[".mpa"] = "video/mpeg"
mime_data[".mpe"] = "video/mpeg"
mime_data[".mpeg"] = "video/mpeg"
mime_data[".mpg"] = "video/mpeg"
mime_data[".mpp"] = "application/vnd.ms-project"
mime_data[".mpv2"] = "video/mpeg"
mime_data[".ms"] = "application/x-troff-ms"
mime_data[".msi"] = "application/octet-stream"
mime_data[".mso"] = "application/octet-stream"
mime_data[".mvb"] = "application/x-msmediaview"
mime_data[".mvc"] = "application/x-miva-compiled"
mime_data[".nc"] = "application/x-netcdf"
mime_data[".nsc"] = "video/x-ms-asf"
mime_data[".nws"] = "message/rfc822"
mime_data[".ocx"] = "application/octet-stream"
mime_data[".oda"] = "application/oda"
mime_data[".odc"] = "text/x-ms-odc"
mime_data[".ods"] = "application/oleobject"
mime_data[".oga"] = "audio/ogg"
mime_data[".ogg"] = "video/ogg"
mime_data[".ogv"] = "video/ogg"
mime_data[".one"] = "application/onenote"
mime_data[".onea"] = "application/onenote"
mime_data[".onetoc"] = "application/onenote"
mime_data[".onetoc2"] = "application/onenote"
mime_data[".onetmp"] = "application/onenote"
mime_data[".onepkg"] = "application/onenote"
mime_data[".osdx"] = "application/opensearchdescription+xml"
mime_data[".otf"] = "font/otf"
mime_data[".p10"] = "application/pkcs10"
mime_data[".p12"] = "application/x-pkcs12"
mime_data[".p7b"] = "application/x-pkcs7-certificates"
mime_data[".p7c"] = "application/pkcs7-mime"
mime_data[".p7m"] = "application/pkcs7-mime"
mime_data[".p7r"] = "application/x-pkcs7-certreqresp"
mime_data[".p7s"] = "application/pkcs7-signature"
mime_data[".pbm"] = "image/x-portable-bitmap"
mime_data[".pcx"] = "application/octet-stream"
mime_data[".pcz"] = "application/octet-stream"
mime_data[".pdf"] = "application/pdf"
mime_data[".pfb"] = "application/octet-stream"
mime_data[".pfm"] = "application/octet-stream"
mime_data[".pfx"] = "application/x-pkcs12"
mime_data[".pgm"] = "image/x-portable-graymap"
mime_data[".pko"] = "application/vnd.ms-pki.pko"
mime_data[".pma"] = "application/x-perfmon"
mime_data[".pmc"] = "application/x-perfmon"
mime_data[".pml"] = "application/x-perfmon"
mime_data[".pmr"] = "application/x-perfmon"
mime_data[".pmw"] = "application/x-perfmon"
mime_data[".png"] = "image/png"
mime_data[".pnm"] = "image/x-portable-anymap"
mime_data[".pnz"] = "image/png"
mime_data[".pot"] = "application/vnd.ms-powerpoint"
mime_data[".potm"] = "application/vnd.ms-powerpoint.template.macroEnabled.12"
mime_data[".potx"] = "application/vnd.openxmlformats-officedocument.presentationml.template"
mime_data[".ppam"] = "application/vnd.ms-powerpoint.addin.macroEnabled.12"
mime_data[".ppm"] = "image/x-portable-pixmap"
mime_data[".pps"] = "application/vnd.ms-powerpoint"
mime_data[".ppsm"] = "application/vnd.ms-powerpoint.slideshow.macroEnabled.12"
mime_data[".ppsx"] = "application/vnd.openxmlformats-officedocument.presentationml.slideshow"
mime_data[".ppt"] = "application/vnd.ms-powerpoint"
mime_data[".pptm"] = "application/vnd.ms-powerpoint.presentation.macroEnabled.12"
mime_data[".pptx"] = "application/vnd.openxmlformats-officedocument.presentationml.presentation"
mime_data[".prf"] = "application/pics-rules"
mime_data[".prm"] = "application/octet-stream"
mime_data[".prx"] = "application/octet-stream"
mime_data[".ps"] = "application/postscript"
mime_data[".psd"] = "application/octet-stream"
mime_data[".psm"] = "application/octet-stream"
mime_data[".psp"] = "application/octet-stream"
mime_data[".pub"] = "application/x-mspublisher"
mime_data[".qt"] = "video/quicktime"
mime_data[".qtl"] = "application/x-quicktimeplayer"
mime_data[".qxd"] = "application/octet-stream"
mime_data[".ra"] = "audio/x-pn-realaudio"
mime_data[".ram"] = "audio/x-pn-realaudio"
mime_data[".rar"] = "application/octet-stream"
mime_data[".ras"] = "image/x-cmu-raster"
mime_data[".rf"] = "image/vnd.rn-realflash"
mime_data[".rgb"] = "image/x-rgb"
mime_data[".rm"] = "application/vnd.rn-realmedia"
mime_data[".rmi"] = "audio/mid"
mime_data[".roff"] = "application/x-troff"
mime_data[".rpm"] = "audio/x-pn-realaudio-plugin"
mime_data[".rtf"] = "application/rtf"
mime_data[".rtx"] = "text/richtext"
mime_data[".scd"] = "application/x-msschedule"
mime_data[".sct"] = "text/scriptlet"
mime_data[".sea"] = "application/octet-stream"
mime_data[".setpay"] = "application/set-payment-initiation"
mime_data[".setreg"] = "application/set-registration-initiation"
mime_data[".sgml"] = "text/sgml"
mime_data[".sh"] = "application/x-sh"
mime_data[".shar"] = "application/x-shar"
mime_data[".sit"] = "application/x-stuffit"
mime_data[".sldm"] = "application/vnd.ms-powerpoint.slide.macroEnabled.12"
mime_data[".sldx"] = "application/vnd.openxmlformats-officedocument.presentationml.slide"
mime_data[".smd"] = "audio/x-smd"
mime_data[".smi"] = "application/octet-stream"
mime_data[".smx"] = "audio/x-smd"
mime_data[".smz"] = "audio/x-smd"
mime_data[".snd"] = "audio/basic"
mime_data[".snp"] = "application/octet-stream"
mime_data[".spc"] = "application/x-pkcs7-certificates"
mime_data[".spl"] = "application/futuresplash"
mime_data[".spx"] = "audio/ogg"
mime_data[".src"] = "application/x-wais-source"
mime_data[".ssm"] = "application/streamingmedia"
mime_data[".sst"] = "application/vnd.ms-pki.certstore"
mime_data[".stl"] = "application/vnd.ms-pki.stl"
mime_data[".sv4cpio"] = "application/x-sv4cpio"
mime_data[".sv4crc"] = "application/x-sv4crc"
mime_data[".svg"] = "image/svg+xml"
mime_data[".svgz"] = "image/svg+xml"
mime_data[".swf"] = "application/x-shockwave-flash"
mime_data[".t"] = "application/x-troff"
mime_data[".tar"] = "application/x-tar"
mime_data[".tcl"] = "application/x-tcl"
mime_data[".tex"] = "application/x-tex"
mime_data[".texi"] = "application/x-texinfo"
mime_data[".texinfo"] = "application/x-texinfo"
mime_data[".tgz"] = "application/x-compressed"
mime_data[".thmx"] = "application/vnd.ms-officetheme"
mime_data[".thn"] = "application/octet-stream"
mime_data[".tif"] = "image/tiff"
mime_data[".tiff"] = "image/tiff"
mime_data[".toc"] = "application/octet-stream"
mime_data[".tr"] = "application/x-troff"
mime_data[".trm"] = "application/x-msterminal"
mime_data[".ts"] = "video/vnd.dlna.mpeg-tts"
mime_data[".tsv"] = "text/tab-separated-values"
mime_data[".ttf"] = "application/octet-stream"
mime_data[".tts"] = "video/vnd.dlna.mpeg-tts"
mime_data[".txt"] = "text/plain"
mime_data[".u32"] = "application/octet-stream"
mime_data[".uls"] = "text/iuls"
mime_data[".ustar"] = "application/x-ustar"
mime_data[".vbs"] = "text/vbscript"
mime_data[".vcf"] = "text/x-vcard"
mime_data[".vcs"] = "text/plain"
mime_data[".vdx"] = "application/vnd.ms-visio.viewer"
mime_data[".vml"] = "text/xml"
mime_data[".vsd"] = "application/vnd.visio"
mime_data[".vss"] = "application/vnd.visio"
mime_data[".vst"] = "application/vnd.visio"
mime_data[".vsto"] = "application/x-ms-vsto"
mime_data[".vsw"] = "application/vnd.visio"
mime_data[".vsx"] = "application/vnd.visio"
mime_data[".vtx"] = "application/vnd.visio"
mime_data[".wav"] = "audio/wav"
mime_data[".wax"] = "audio/x-ms-wax"
mime_data[".wbmp"] = "image/vnd.wap.wbmp"
mime_data[".wcm"] = "application/vnd.ms-works"
mime_data[".wdb"] = "application/vnd.ms-works"
mime_data[".webm"] = "video/webm"
mime_data[".wks"] = "application/vnd.ms-works"
mime_data[".wm"] = "video/x-ms-wm"
mime_data[".wma"] = "audio/x-ms-wma"
mime_data[".wmd"] = "application/x-ms-wmd"
mime_data[".wmf"] = "application/x-msmetafile"
mime_data[".wml"] = "text/vnd.wap.wml"
mime_data[".wmlc"] = "application/vnd.wap.wmlc"
mime_data[".wmls"] = "text/vnd.wap.wmlscript"
mime_data[".wmlsc"] = "application/vnd.wap.wmlscriptc"
mime_data[".wmp"] = "video/x-ms-wmp"
mime_data[".wmv"] = "video/x-ms-wmv"
mime_data[".wmx"] = "video/x-ms-wmx"
mime_data[".wmz"] = "application/x-ms-wmz"
mime_data[".woff"] = "font/x-woff"
mime_data[".wps"] = "application/vnd.ms-works"
mime_data[".wri"] = "application/x-mswrite"
mime_data[".wrl"] = "x-world/x-vrml"
mime_data[".wrz"] = "x-world/x-vrml"
mime_data[".wsdl"] = "text/xml"
mime_data[".wtv"] = "video/x-ms-wtv"
mime_data[".wvx"] = "video/x-ms-wvx"
mime_data[".x"] = "application/directx"
mime_data[".xaf"] = "x-world/x-vrml"
mime_data[".xaml"] = "application/xaml+xml"
mime_data[".xap"] = "application/x-silverlight-app"
mime_data[".xbap"] = "application/x-ms-xbap"
mime_data[".xbm"] = "image/x-xbitmap"
mime_data[".xdr"] = "text/plain"
mime_data[".xht"] = "application/xhtml+xml"
mime_data[".xhtml"] = "application/xhtml+xml"
mime_data[".xla"] = "application/vnd.ms-excel"
mime_data[".xlam"] = "application/vnd.ms-excel.addin.macroEnabled.12"
mime_data[".xlc"] = "application/vnd.ms-excel"
mime_data[".xlm"] = "application/vnd.ms-excel"
mime_data[".xls"] = "application/vnd.ms-excel"
mime_data[".xlsb"] = "application/vnd.ms-excel.sheet.binary.macroEnabled.12"
mime_data[".xlsm"] = "application/vnd.ms-excel.sheet.macroEnabled.12"
mime_data[".xlsx"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
mime_data[".xlt"] = "application/vnd.ms-excel"
mime_data[".xltm"] = "application/vnd.ms-excel.template.macroEnabled.12"
mime_data[".xltx"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.template"
mime_data[".xlw"] = "application/vnd.ms-excel"
mime_data[".xml"] = "text/xml"
mime_data[".xof"] = "x-world/x-vrml"
mime_data[".xpm"] = "image/x-xpixmap"
mime_data[".xps"] = "application/vnd.ms-xpsdocument"
mime_data[".xsd"] = "text/xml"
mime_data[".xsf"] = "text/xml"
mime_data[".xsl"] = "text/xml"
mime_data[".xslt"] = "text/xml"
mime_data[".xsn"] = "application/octet-stream"
mime_data[".xtp"] = "application/octet-stream"
mime_data[".xwd"] = "image/x-xwindowdump"
mime_data[".z"] = "application/x-compress"
mime_data[".zip"] = "application/x-zip-compressed"
# ------------------audio-------------------------
mime_data[".weba"] = "audio/webm"

# ----Image ---------------------------------
mime_data[".webp"] = "image/webp"
mime_data[".avif"] = "image/avif"

mimetypes.types_map = {**mime_data, **mimetypes.types_map}
__old__ = mimetypes.guess_type


def __new__fn__(url, strict=True):
    import os
    items = url.split('.')
    item = "." + items[items.__len__() - 1]
    a, b = mime_data.get(item), None
    if a is None:
        a, b = __old__(url, strict)
    if a is None:
        x = os.path.splitext(url)[1]
        a = mime_data.get(x)
        if a is None:
            a = r'application/octet-stream'
    return a, b


mimetypes.guess_type = __new__fn__
"""
all re definre hear
"""
def is_package(path_to_dir:str):
    if not os.path.isdir(path_to_dir):
        return False
    return os.path.isfile(os.path.join(path_to_dir,"__init__.py"))
def get_root_package_dir(from_path:str):
    ret=""
    from_path=os.path.abspath(from_path)
    if os.path.isfile(from_path):
        from_path=pathlib.Path(from_path).parent.__str__()
    while is_package(from_path):
        parent=pathlib.Path(from_path).parent.__str__()
        name = from_path[parent.__len__():]
        ret=name+ret
        from_path = parent
    ret=ret.replace(os.sep,'/').replace('/','.')
    ret=ret[1:]
    return ret,from_path
from fastapi.middleware.cors import CORSMiddleware

import logging
from fastapi.exceptions import HTTPException
from typing import List
import typing
import uvicorn
import jose
from jose import JWTError, jwt
import threading
from datetime import datetime
import inspect
import fastapi
import pydantic
import sys




def get_cls(cls):
    if sys.modules.get(cls.__module__):
        mdl = sys.modules[cls.__module__]
        if not hasattr(cls, "__name__"):
            return
        if hasattr(mdl, cls.__name__):
            ret = getattr(mdl, cls.__name__)
            if issubclass(ret, pydantic.BaseModel):
                return ret

def get_mdl(cls):
        if sys.modules.get(cls.__module__):
            return sys.modules[cls.__module__]
        else:
            for k, v in sys.modules.items():
                if hasattr(v, "__file__"):
                    if v.__file__ == cls.__module__:
                        return v
def __wrap_pydantic__(pre, cls, is_lock=True):
    cls_module = get_mdl(cls)
    global __wrap_pydantic_cache__
    global __wrap_pydantic_lock__
    if cls.__module__ == typing.__name__ and cls.__origin__ == list:
        ret = []
        for x in cls.__args__:
            ret += [__wrap_pydantic__("", x)]
        cls.__args__ = tuple(ret)
        return cls


    if hasattr(cls, "__annotations__"):
        ls = list(cls.__dict__.items())
        for k, v in ls:
            if not (k[0:2] == "__" and k[:-2] != "__") and v not in [str, int, datetime, bool,
                                                                     float] and inspect.isclass(v):
                re_modify = __wrap_pydantic__(cls.__name__, v, False)
                cls.__annotations__[k] = re_modify
                setattr(sys.modules[cls.__module__], k, re_modify)

        for k, v in cls.__annotations__.items():
            if v.__module__ == typing.__name__:
                temp = []
                for fv in v.__args__:

                    if check_is_need_pydantic(fv):
                        if get_cls(fv) is None:
                            re_modify = __wrap_pydantic__(cls.__name__, fv, False)
                            # setattr(sys.modules[fv.__module__],fv.__name__,re_modify)
                            # setattr(sys.modules[cls.__module__], fv.__name__, re_modify)

                            temp += [re_modify]
                        else:
                            temp += [get_cls(fv)]
                    else:
                        temp += [fv]
                # v.__args__ =tuple(temp)
                cls.__annotations__[k].__args__ = tuple(temp)




            elif v not in [str, int, datetime, bool, float] and inspect.isclass(v):
                if cls.__annotations__.get(k) is not None:
                    if get_cls(cls) is None:
                        re_modify = __wrap_pydantic__(cls.__name__, v, False)
                        cls.__annotations__[k] = re_modify
                        setattr(sys.modules[re_modify.__module__], k, re_modify)

    ret_cls = type(f"{cls.__name__}", (cls, pydantic.BaseModel,), dict(cls.__dict__))




    setattr(cls_module, cls.__name__, ret_cls)
    ret_cls.__name__ = cls.__name__
    cls=ret_cls
    return cls


def check_is_need_pydantic(cls):
    if inspect.isclass(cls):
        if cls.__module__ == bytes.__module__ and cls.__name__ == "NoneType":
            return False
    import typing
    if isinstance(cls, tuple):
        ret = False
        for x in cls:
            ret = ret or check_is_need_pydantic(x)
        return ret
    if cls.__module__ == typing.__name__ and cls.__origin__ == list and hasattr(cls, "__args__"):
        return check_is_need_pydantic(cls.__args__)
    if cls == fastapi.Request or issubclass(cls, fastapi.Request):
        return False
    if not inspect.isclass(cls) and callable(cls):
        return False
    if hasattr(cls, "__origin__") and cls.__origin__ == typing.List.__origin__ and hasattr(cls,
                                                                                           "__args__") and isinstance(
        cls.__args__, tuple):
        ret = []
        for x in cls.__args__:
            if check_is_need_pydantic(x):
                ret += [__wrap_pydantic__("", x, is_lock=False)]
            else:
                ret += [x]
        cls.__args__ = tuple(ret)

        return False

    ret = (cls not in [str, int, float, datetime, bool, dict, bytes]) and (
            inspect.isclass(cls) and (not issubclass(cls, pydantic.BaseModel)))
    return ret


class RequestHandler:

    def __init__(self, method, path, handler):
        self.path = path
        __old_dfs__ = []
        self.return_type = None
        if handler.__defaults__ is not None:
            pos = 0
            tmp_lst = list(handler.__defaults__)
            for x in handler.__defaults__:

                if type(x) == fastapi.params.File:
                    method = "form"

                if inspect.isclass(x) and issubclass(x, fastapi.UploadFile):
                    tmp_lst[pos] = fastapi.File()
                    method = "form"

                pos += 1
            tmp_lst += [fastapi.Depends()]
            handler.__defaults__ = tuple(tmp_lst)

            __old_dfs__ = list(handler.__defaults__)
        __annotations__: dict = handler.__annotations__
        __defaults__ = []
        for k, v in __annotations__.items():
            if inspect.isclass(v) and issubclass(v, fastapi.UploadFile):
                method = "form"
                break
        for k, v in __annotations__.items():

            if method != "form":
                if v == fastapi.Request:
                    continue
                if check_is_need_pydantic(v):
                    handler.__annotations__[k] = __wrap_pydantic__("", v)
                    if k != "return":
                        __defaults__ += [fastapi.Body(title=k)]

                    else:
                        self.return_type = handler.__annotations__[k]

            else:
                if k == "return":
                    if check_is_need_pydantic(v):
                        handler.__annotations__[k] = __wrap_pydantic__("", v)

                if not "{" + k + "}" in self.path:
                    import typing
                    if v == fastapi.UploadFile or v == fastapi.Request or \
                            (hasattr(v, "__origin__") and v.__origin__ == typing.List[fastapi.UploadFile].__origin__
                             and hasattr(v, "__args__") and v.__args__[0] == fastapi.UploadFile):
                        continue
                    elif k != "return" and not v in [str, datetime, bool, float, int]:
                        continue
                    elif k != "return":
                        __defaults__ += [fastapi.Form()]
                        # __wrap_pydantic__(handler.__name__, v)

        __defaults__ += __old_dfs__
        # def new_handler(*args,**kwargs):
        #     handler(*args,**kwargs)
        handler.__defaults__ = tuple(__defaults__)
        self.handler = handler
        if method == "form": method = "post"
        self.method = method


def __wrapper_class__(method: str, obj, path: str):
    pass


def __wrapper_func__(method: str, obj, path) -> RequestHandler:
    fx = RequestHandler(method, path, obj)
    return fx


from fastapi import FastAPI, Request

from typing import Optional, Dict
from fastapi.security.oauth2 import OAuth2PasswordBearer
import fastapi.params
import os
from fastapi.templating import Jinja2Templates


# wellknown_app: FastAPI = None
# __instance__ = None


def load_controller_from_file(file):
    if not os.path.isfile(file):
        print(f"{file} was not found")
        logging.Logger.error(f"{file} was not found")
    pass


class BaseWebApp:
    def __init__(self):
        self.application_name = None
        self.main_module = None
        self.bind_ip = None
        self.bind_port = None
        self.host_url = None
        self.host_api_url = None
        self.host_schema = None
        self.__routers__ = None
        self.app: FastAPI = None
        self.controller_dirs: List[str] = []
        self.logs_dir: str = None
        self.logs: logging.Logger = None
        self.working_dir: str = None
        self.host_dir: str = None
        self.dev_mode: bool = False
        self.api_host_dir = "api"
        self.static_dir: str = None
        self.template_dir: str = None
        self.templates: Jinja2Templates = None
        self.url_get_token: str = None

        self.jwt_algorithm = "HS256"
        self.jwt_secret_key = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
        self.oauth2_type = None
        self.__on_auth__ = None
        self.request_handlers = dict()
        self.on_auth_user = None

    def load_controller_from_dir(self, route_prefix: str = None, controller_dir: str = None):
        if controller_dir == None:
            return
        if controller_dir[0:2] == "./":
            controller_dir = os.path.join(self.working_dir, controller_dir[2:])
        controller_dir = controller_dir.replace('/', os.sep)
        if not os.path.isdir(controller_dir):
            print(f"{controller_dir} was not found")
            self.logs.error(msg=f"{controller_dir} was not found")
            return
        root_dir, dirs, files = list(os.walk(controller_dir))[0]
        import sys
        sys.path.append(self.working_dir)
        sys.path.append(root_dir)
        for x in dirs:
            sys.path.append(x)
        for _file_ in files:
            self.load_controller_from_file(os.path.join(root_dir, _file_), route_prefix)
        for dir in dirs:
            self.load_controller_module_dir(os.path.join(root_dir, dir), route_prefix)

    def create_logs(self, logs_dir) -> logging.Logger:
        if not os.path.isdir(logs_dir):
            os.makedirs(logs_dir, exist_ok=True)

        _logs = logging.Logger("web")
        hdlr = logging.FileHandler(logs_dir + '/log{}.txt'.format(datetime.strftime(datetime.now(), '%Y%m%d%H%M%S_%f')))
        _logs.addHandler(hdlr)
        return _logs

    def load_controller_module_dir(self, module_dir, prefix: str = None) -> List[object]:

        # import pyx_re_quicky_routers
        module_path = os.path.join(module_dir, "__init__.py")
        _, _, files = list(os.walk(module_dir))[0]
        for _file_ in files:
            if os.path.splitext(_file_)[1] == ".py":
                full_file_path = os.path.join(module_dir, _file_)
                if os.path.isfile(full_file_path):
                    self.load_controller_from_file(full_file_path, prefix)

    def auth(self):
        def wrapper(fn):
            setattr(self.oauth2_type, "__call__", fn)

        return wrapper



    def load_controller_from_file(self, full_file_path, prefix):

        if not os.path.isfile(full_file_path):
            return
        if os.path.splitext(full_file_path).__len__() != 2 and os.path.splitext(full_file_path)[1] != ".py":
            return
        import importlib.util
        from importlib import machinery
        import sys
        src = machinery.SourceFileLoader(full_file_path, full_file_path)

        spec = importlib.util.spec_from_loader(full_file_path, src)
        _mdl_ = importlib.util.module_from_spec(spec)

        sys.modules[_mdl_.__name__] = _mdl_
        if hasattr(sys.modules[_mdl_.__name__], "__cy_web_has_load_controller__"):
            return
        __cy_web_has_load_controller__ = False

        spec.loader.exec_module(_mdl_)
        for k, v in _mdl_.__dict__.items():
            if isinstance(v, RequestHandler):

                __cy_web_has_load_controller__ = True
                _path = "/" + v.path
                if prefix is not None and prefix != "":
                    _path = "/" + prefix + _path
                if self.host_dir is not None:
                    _path = self.host_dir + _path
                if v.return_type is None:
                    if hasattr(v.handler, "__annotations__"):
                        if v.handler.__annotations__.get("return") is not None:
                            v.return_type = v.handler.__annotations__.get("return")

                if v.return_type is not None:

                    getattr(self.app, v.method)(_path, response_model=v.return_type)(v.handler)
                else:

                    getattr(self.app, v.method)(_path)(v.handler)
                self.request_handlers[v.path] = v
        if __cy_web_has_load_controller__:
            setattr(sys.modules[_mdl_.__name__], "__cy_web_has_load_controller__", True)


__cache_apps__ = {}
__cache_apps_lock__ = threading.Lock()
__instance__ = None
web_application = None
from fastapi import Depends, FastAPI, HTTPException, status
from datetime import datetime, timedelta
from typing import Union
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm


def create_access_token(data: dict, expires_delta=None, SECRET_KEY=None, ALGORITHM=None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": None})
    encoded_jwt = jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def login_for_access_token(request:fastapi.Request, form_data: OAuth2PasswordRequestForm = Depends()):
    global web_application
    if not isinstance(web_application, WebApp):
        raise Exception("WebApp was not found")
    if web_application.on_auth_user is None:
        raise Exception("Please create on auth user with  cy_web_x.auth_user")
    user = web_application.on_auth_user(request,form_data.username, form_data.password)
    if not isinstance(user, dict):
        raise Exception(
            f"{web_application.on_auth_user.__name__} in {web_application.on_auth_user.__code__.co_filename} must return dictionary with username:str and application:str,is_ok:bool")
    if set(["username", "application", "is_ok"]).intersection(list(user.keys())) != set(
            ["username", "application", "is_ok"]):
        raise Exception(
            f"{web_application.on_auth_user.__name__} in {web_application.on_auth_user.__code__.co_filename} must return dictionary with username:str and application:str,is_ok:bool")
    if user.get("is_ok") == False:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        {
            "username": user.get("username"),
            "application": user.get("application")
        }, expires_delta=None,
        SECRET_KEY=web_application.jwt_secret_key,
        ALGORITHM=web_application.jwt_algorithm
    )
    return {"access_token": access_token, "token_type": "bearer"}


class WebApp(BaseWebApp):

    def __init__(self,

                 working_dir: str,
                 bind: str = "0.0.0.0:8011",
                 host_url: str = "http://localhost:8011",
                 logs_dir: str = "./logs",
                 controller_dirs: List[str] = [],
                 api_host_dir: str = "api",
                 static_dir: str = None,
                 dev_mode: bool = False,
                 template_dir: str = None,
                 url_get_token: str = "api/accounts/token",
                 jwt_algorithm: str = "HS256",
                 jwt_secret_key: str = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
                 ):
        global __cache_apps__
        global __cache_apps_lock__
        global web_application
        web_application = self
        self.request_handlers = dict()
        self.app = fastapi.FastAPI()
        self.url_get_token = url_get_token
        self.jwt_algorithm = jwt_algorithm
        self.jwt_secret_key = jwt_secret_key
        self.template_dir = template_dir
        self.dev_mode = dev_mode
        self.api_host_dir = api_host_dir

        self.working_dir = working_dir
        root_package, root_package_dir = get_root_package_dir(self.working_dir)
        self.root_package_dir=root_package_dir
        self.root_package=root_package

        self.static_dir = static_dir
        if self.static_dir is not None and self.static_dir[0:2] == "./":
            self.static_dir = os.path.join(self.working_dir, self.static_dir[2:])
        self.logs_dir = logs_dir
        if self.logs_dir[0:2] == "./":
            self.logs_dir = os.path.join(self.working_dir, self.logs_dir[2:])
        self.logs: logging.Logger = self.create_logs(self.logs_dir)
        if bind.split(":").__len__() < 2:
            raise Exception(f"bind in {self.__module__}.{WebApp.__name__}.__init__ must look like 0.0.0.0:1234")
        self.bind_ip = bind.split(':')[0]
        self.bind_port = int(bind.split(':')[1])
        self.host_url = host_url
        self.host_schema = self.host_url.split(f"://")[0]
        remain = self.host_url[self.host_schema.__len__() + 3:]
        self.host_name = remain.split('/')[0].split(':')[0]
        self.host_port = None
        self.host_api_url = self.host_url + "/" + self.api_host_dir
        if remain.split('/')[0].split(':').__len__() == 2:
            self.host_port = int(remain.split('/')[0].split(':')[1])
            remain = remain[self.host_name.__len__() + str(self.host_port).__len__() + 1:]
        self.host_dir = None
        if remain != "":
            self.host_dir = remain

        if self.static_dir is not None:
            from fastapi.staticfiles import StaticFiles
            if self.host_dir is not None and self.host_dir != "":
                self.app.mount(self.host_dir + "/static", StaticFiles(directory=self.static_dir), name="static")
            else:
                self.app.mount("/static", StaticFiles(directory=self.static_dir),
                               name="static")
        if self.template_dir is not None and self.template_dir[0:2] == "./":
            self.template_dir = os.path.join(self.working_dir, self.template_dir[2:])
        if self.template_dir is not None:
            self.templates = Jinja2Templates(directory=self.template_dir)

        self.controller_dirs = []
        for x in controller_dirs:
            if x[0:2] == "./":
                self.controller_dirs += [
                    os.path.join(self.working_dir, x[2:])
                ]
            else:
                self.controller_dirs += [x]
        for x in self.controller_dirs:
            self.load_controller_from_dir(x)
        if self.host_dir is not None and self.host_dir != "":
            self.url_get_token = self.host_dir + "/" + self.url_get_token


        self.app.post("/" + self.url_get_token)(login_for_access_token)

    def unvicorn_start(self, start_path):
        global web_application
        # for k,v in self.web_app_module.__dict__.items():
        #     if v==self:
        #        self.web_app_name=k
        run_path = f"{start_path}:web_application.app"
        if self.dev_mode:
            uvicorn.run(
                run_path,
                host=self.bind_ip,
                port=self.host_port,
                log_level="info",
                workers=8,
                lifespan='on',
                reload=self.dev_mode,
                reload_dirs=self.working_dir

            )
        else:
            uvicorn.run(
                run_path,
                host=self.bind_ip,
                port=self.host_port,
                log_level="info",
                workers=8,
                lifespan='on'

            )


def web_handler(path: str, method: str, response_model=None):
    def warpper(obj):
        import inspect
        if inspect.isclass(obj):
            return __wrapper_class__(method, obj, path)
        elif callable(obj):
            # fx= fastapi.FastAPI()
            # fx.get(response_model=)

            return __wrapper_func__(method, obj, path)

    return warpper


def add_controller(web_app, prefix_path: str, controller_dir):
    web_app.load_controller_from_dir(prefix_path, controller_dir)


def start_with_uvicorn():
    global web_application
    if isinstance(web_application, WebApp):
        web_application.unvicorn_start(
            f"{WebApp.__module__}"
        )
    # run_path=path.replace(os.sep,"/").replace('/','.')
    # web_app.unvicorn_start(run_path)


def load_controller_from_dir(prefix, controller_path):
    global web_application
    if isinstance(web_application, WebApp):
        web_application.load_controller_from_dir(
            prefix, controller_path
        )


def middleware():
    global web_application
    if isinstance(web_application, WebApp):
        return web_application.app.middleware("http")








def fast_api() -> fastapi.FastAPI:
    global web_application
    if isinstance(web_application, WebApp):
        return web_application.app


def add_cors(origins: List[str]):
    global web_application
    if isinstance(web_application, WebApp):
        web_application.app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )


def get_host_url() -> str:
    global web_application
    if isinstance(web_application, WebApp):
        return web_application.host_url


def get_host_dir() -> str:
    global web_application
    if isinstance(web_application, WebApp):
        return web_application.host_dir


def get_working_dir() -> str:
    global web_application
    if isinstance(web_application, WebApp):
        return web_application.working_dir


def get_template_dir() -> str:
    global web_application
    if isinstance(web_application, WebApp):
        return web_application.template_dir


def get_template_dir() -> int:
    global web_application
    if isinstance(web_application, WebApp):
        return web_application.host_port


def get_bind_ip() -> str:
    global web_application
    if isinstance(web_application, WebApp):
        return web_application.bind_ip


def get_fastapi_app() -> FastAPI:
    global web_application
    if isinstance(web_application, WebApp):
        return web_application.app


def render_template(rel_path_to_template_page: str, render_data: dict):
    global web_application
    if isinstance(web_application, WebApp):
        return web_application.templates.TemplateResponse(
            rel_path_to_template_page,
            render_data

        )


def get_static_dir():
    global web_application
    if isinstance(web_application, WebApp):
        return web_application.static_dir


def get_token_url():
    global web_application
    if isinstance(web_application, WebApp):
        return web_application.url_get_token


def get_jwt_secret_key():
    global web_application
    if isinstance(web_application, WebApp):
        return web_application.jwt_secret_key


def get_jwt_algorithm():
    global web_application
    if isinstance(web_application, WebApp):
        return web_application.jwt_algorithm

import starlette.requests
def validate_token_in_request(self, request):
    token = None
    if request.cookies.get('access_token_cookie', None) is not None:
        token = request.cookies['access_token_cookie']
    else:
        authorization: str = request.headers.get("Authorization")
        if authorization is None:
            raise fastapi.exceptions.HTTPException(status_code=401)
        scheme, token = tuple(authorization.split(' '))
        if not authorization or scheme.lower() != "bearer":
            if self.auto_error:
                raise HTTPException(
                    status_code=401,
                    detail="Not authenticated",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            else:
                return None
    try:

        ret_data = jwt.decode(token, self.jwt_secret_key,
                              algorithms=[self.jwt_algorithm],
                              options={"verify_signature": False},
                              )
        username = ret_data.get("username")
        application = ret_data.get("application")
        setattr(request, "username", username)
        setattr(request, "application", application)
        if self.validate(request,ret_data.get("username"), ret_data.get("application")):
            return dict(token=token, username=username, application=application)
        else:
            raise HTTPException(
                status_code=401,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except jose.exceptions.ExpiredSignatureError as e:
        raise HTTPException(
            status_code=401,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )


def auth_type(a_type: type):
    def default_init(ins):
        global web_application
        assert isinstance(web_application, WebApp)
        a_type.__init__(ins, web_application.url_get_token)

    def wrapper(cls):
        global web_application
        assert isinstance(web_application, WebApp)
        cls = type(f"{cls.__name__}", (cls, a_type), {})
        if not hasattr(cls,"validate"):
            raise Exception(f"{cls.__module__}.{cls.__name__} must have validate function looks like:\n"
                            f"def validate(self,request:fastapi.Request,username:str,application:str)->bool:\n"
                            f" blab ...")
        validate = getattr(cls, "validate")
        setattr(cls, "__init__", default_init)
        validate_token_in_request.__annotations__["request"] = validate.__annotations__["request"]
        setattr(cls, "__call__", validate_token_in_request)
        instance = cls()
        setattr(instance,"jwt_secret_key",web_application.jwt_secret_key)
        setattr(instance, "jwt_algorithm", web_application.jwt_algorithm)
        def on_auth_user(request,username,password):
            instance.validate_account(request,username,password)
        web_application.on_auth_user=on_auth_user
        return instance


    return wrapper
def model():
    def warpper(cls):
        return __wrap_pydantic__("",cls,False)
    return warpper