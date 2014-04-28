/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*-
 * vim: set ts=4 sw=4 et tw=99 ft=cpp:
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "AccessCheck.h"

#include "nsJSPrincipals.h"
#include "nsGlobalWindow.h"

#include "XPCWrapper.h"
#include "XrayWrapper.h"

#include "jsfriendapi.h"
#include "mozilla/dom/BindingUtils.h"
#include "mozilla/dom/WindowBinding.h"
#include "nsIDOMWindowCollection.h"
#include "nsJSUtils.h"

using namespace mozilla;
using namespace JS;
using namespace js;

namespace xpc {

nsIPrincipal *
GetCompartmentPrincipal(JSCompartment *compartment)
{
    return nsJSPrincipals::get(JS_GetCompartmentPrincipals(compartment));
}

nsIPrincipal *
GetObjectPrincipal(JSObject *obj)
{
    return GetCompartmentPrincipal(js::GetObjectCompartment(obj));
}

// Does the principal of compartment a subsume the principal of compartment b?
bool
AccessCheck::subsumes(JSCompartment *a, JSCompartment *b)
{
    nsIPrincipal *aprin = GetCompartmentPrincipal(a);
    nsIPrincipal *bprin = GetCompartmentPrincipal(b);
    return aprin->Subsumes(bprin);
}

bool
AccessCheck::subsumes(JSObject *a, JSObject *b)
{
    return subsumes(js::GetObjectCompartment(a), js::GetObjectCompartment(b));
}

// Same as above, but considering document.domain.
bool
AccessCheck::subsumesConsideringDomain(JSCompartment *a, JSCompartment *b)
{
    nsIPrincipal *aprin = GetCompartmentPrincipal(a);
    nsIPrincipal *bprin = GetCompartmentPrincipal(b);
    return aprin->SubsumesConsideringDomain(bprin);
}

// Does the compartment of the wrapper subsumes the compartment of the wrappee?
bool
AccessCheck::wrapperSubsumes(JSObject *wrapper)
{
    MOZ_ASSERT(js::IsWrapper(wrapper));
    JSObject *wrapped = js::UncheckedUnwrap(wrapper);
    return AccessCheck::subsumes(js::GetObjectCompartment(wrapper),
                                 js::GetObjectCompartment(wrapped));
}

bool
AccessCheck::isChrome(JSCompartment *compartment)
{
    nsIScriptSecurityManager *ssm = XPCWrapper::GetSecurityManager();
    if (!ssm) {
        return false;
    }

    bool privileged;
    nsIPrincipal *principal = GetCompartmentPrincipal(compartment);
    return NS_SUCCEEDED(ssm->IsSystemPrincipal(principal, &privileged)) && privileged;
}

bool
AccessCheck::isChrome(JSObject *obj)
{
    return isChrome(js::GetObjectCompartment(obj));
}

bool
AccessCheck::callerIsChrome()
{
    nsIScriptSecurityManager *ssm = XPCWrapper::GetSecurityManager();
    if (!ssm)
        return false;
    bool subjectIsSystem;
    nsresult rv = ssm->SubjectPrincipalIsSystem(&subjectIsSystem);
    return NS_SUCCEEDED(rv) && subjectIsSystem;
}

nsIPrincipal *
AccessCheck::getPrincipal(JSCompartment *compartment)
{
    return GetCompartmentPrincipal(compartment);
}

#define NAME(ch, str, cases)                                                  \
    case ch: if (!strcmp(name, str)) switch (propChars[0]) { cases }; break;
#define PROP(ch, actions) case ch: { actions }; break;
#define RW(str) if (JS_FlatStringEqualsAscii(prop, str)) return true;
#define R(str) if (!set && JS_FlatStringEqualsAscii(prop, str)) return true;
#define W(str) if (set && JS_FlatStringEqualsAscii(prop, str)) return true;

// Hardcoded policy for cross origin property access. This was culled from the
// preferences file (all.js). We don't want users to overwrite highly sensitive
// security policies.
static bool
IsPermitted(const char *name, JSFlatString *prop, bool set)
{
    size_t propLength;
    const jschar *propChars =
        JS_GetInternedStringCharsAndLength(JS_FORGET_STRING_FLATNESS(prop), &propLength);
    if (!propLength)
        return false;
    switch (name[0]) {
        NAME('L', "Location",
             PROP('h', W("href"))
             PROP('r', R("replace")))
        case 'W':
            if (!strcmp(name, "Window"))
                return dom::WindowBinding::IsPermitted(prop, propChars[0], set);
            break;
    }
    return false;
}

static bool
IsPostMessage(const char *name, JSFlatString *prop)
{
    size_t propLength;
    const jschar *propChars =
        JS_GetInternedStringCharsAndLength(JS_FORGET_STRING_FLATNESS(prop), &propLength);
    if (!propLength)
        return false;
    bool set = false;
    switch (name[0]) {
        NAME('W', "Window",
             PROP('p', R("postMessage")))
    }
    return false;
}

static bool
IsAddonSDK(JSContext *cx, JSCompartment *compartment)
{ 
    RootedObject sandbox(cx, js::CheckedUnwrap(JS_GetGlobalForCompartmentOrNull(compartment)));
    if (sandbox && xpc::IsSandbox(sandbox)) {
        RootedValue metadata(cx);
        nsresult rv = xpc::GetSandboxMetadata(cx, sandbox, &metadata);
        if (NS_SUCCEEDED(rv) && metadata.isObject()) {
            RootedObject obj(cx, &metadata.toObject());
            RootedValue addonID(cx);
            return JS_GetProperty(cx, obj, "addonID", &addonID) &&
                   !JSVAL_IS_VOID(addonID);
        }
    }
    return false;
}

#undef NAME
#undef RW
#undef R
#undef W

static bool
IsFrameId(JSContext *cx, JSObject *objArg, jsid idArg)
{
    RootedObject obj(cx, objArg);
    RootedId id(cx, idArg);

    obj = JS_ObjectToInnerObject(cx, obj);
    MOZ_ASSERT(!js::IsWrapper(obj));
    nsGlobalWindow* win = WindowOrNull(obj);
    if (!win) {
        return false;
    }

    nsCOMPtr<nsIDOMWindowCollection> col;
    win->GetFrames(getter_AddRefs(col));
    if (!col) {
        return false;
    }

    nsCOMPtr<nsIDOMWindow> domwin;
    if (JSID_IS_INT(id)) {
        col->Item(JSID_TO_INT(id), getter_AddRefs(domwin));
    } else if (JSID_IS_STRING(id)) {
        col->NamedItem(nsDependentJSString(id), getter_AddRefs(domwin));
    }

    return domwin != nullptr;
}

static bool
IsWindow(const char *name)
{
    return name[0] == 'W' && !strcmp(name, "Window");
}

bool
AccessCheck::isCrossOriginAccessPermitted(JSContext *cx, JSObject *wrapperArg, jsid idArg,
                                          Wrapper::Action act)
{
    if (!XPCWrapper::GetSecurityManager())
        return true;

    if (act == Wrapper::CALL)
        return false;

    RootedId id(cx, idArg);
    RootedObject wrapper(cx, wrapperArg);
    RootedObject obj(cx, Wrapper::wrappedObject(wrapper));

    // For XOWs, we generally want to deny enumerate-like operations, but fail
    // silently (see CrossOriginAccessiblePropertiesOnly::deny).
    if (act == Wrapper::ENUMERATE)
        return false;

    const char *name;
    const js::Class *clasp = js::GetObjectClass(obj);
    MOZ_ASSERT(!XrayUtils::IsXPCWNHolderClass(Jsvalify(clasp)), "shouldn't have a holder here");
    if (clasp->ext.innerObject)
        name = "Window";
    else
        name = clasp->name;

    if (JSID_IS_STRING(id)) {
        if (IsPermitted(name, JSID_TO_FLAT_STRING(id), act == Wrapper::SET))
            return true;
    }

    if (act != Wrapper::GET)
        return false;

    // Check for frame IDs. If we're resolving named frames, make sure to only
    // resolve ones that don't shadow native properties. See bug 860494.
    if (IsWindow(name)) {
        if (JSID_IS_STRING(id) && !XrayUtils::IsXrayResolving(cx, wrapper, id)) {
            bool wouldShadow = false;
            if (!XrayUtils::HasNativeProperty(cx, wrapper, id, &wouldShadow) ||
                wouldShadow)
            {
                return false;
            }
        }
        return IsFrameId(cx, obj, id);
    }
    return false;
}

enum Access { READ = (1<<0), WRITE = (1<<1), NO_ACCESS = 0 };

static void
EnterAndThrow(JSContext *cx, JSObject *wrapper, const char *msg)
{
    JSAutoCompartment ac(cx, wrapper);
    JS_ReportError(cx, msg);
}

bool
ExposedPropertiesOnly::check(JSContext *cx, JSObject *wrapperArg, jsid idArg, Wrapper::Action act)
{
    RootedObject wrapper(cx, wrapperArg);
    RootedId id(cx, idArg);
    RootedObject wrappedObject(cx, Wrapper::wrappedObject(wrapper));

    if (act == Wrapper::CALL)
        return true;

    RootedId exposedPropsId(cx, GetRTIdByIndex(cx, XPCJSRuntime::IDX_EXPOSEDPROPS));

    // We need to enter the wrappee's compartment to look at __exposedProps__,
    // but we want to be in the wrapper's compartment if we call Deny().
    //
    // Unfortunately, |cx| can be in either compartment when we call ::check. :-(
    JSAutoCompartment ac(cx, wrappedObject);

    bool found = false;
    if (!JS_HasPropertyById(cx, wrappedObject, exposedPropsId, &found))
        return false;

    // Always permit access to "length" and indexed properties of arrays.
    if ((JS_IsArrayObject(cx, wrappedObject) ||
         JS_IsTypedArrayObject(wrappedObject)) &&
        ((JSID_IS_INT(id) && JSID_TO_INT(id) >= 0) ||
         (JSID_IS_STRING(id) && JS_FlatStringEqualsAscii(JSID_TO_FLAT_STRING(id), "length")))) {
        return true; // Allow
    }

    // If no __exposedProps__ existed, deny access.
    if (!found) {
        return false;
    }

    if (id == JSID_VOID)
        return true;

    RootedValue exposedProps(cx);
    if (!JS_LookupPropertyById(cx, wrappedObject, exposedPropsId, &exposedProps))
        return false;

    if (exposedProps.isNullOrUndefined())
        return false;

    if (!exposedProps.isObject()) {
        EnterAndThrow(cx, wrapper, "__exposedProps__ must be undefined, null, or an Object");
        return false;
    }

    RootedObject hallpass(cx, &exposedProps.toObject());

    if (!AccessCheck::subsumes(js::UncheckedUnwrap(hallpass), wrappedObject)) {
        EnterAndThrow(cx, wrapper, "Invalid __exposedProps__");
        return false;
    }

    Access access = NO_ACCESS;

    Rooted<JSPropertyDescriptor> desc(cx);
    if (!JS_GetPropertyDescriptorById(cx, hallpass, id, 0, &desc)) {
        return false; // Error
    }
    if (!desc.object() || !desc.isEnumerable())
        return false;

    if (!desc.value().isString()) {
        EnterAndThrow(cx, wrapper, "property must be a string");
        return false;
    }

    JSString *str = desc.value().toString();
    size_t length;
    const jschar *chars = JS_GetStringCharsAndLength(cx, str, &length);
    if (!chars)
        return false;

    for (size_t i = 0; i < length; ++i) {
        switch (chars[i]) {
        case 'r':
            if (access & READ) {
                EnterAndThrow(cx, wrapper, "duplicate 'readable' property flag");
                return false;
            }
            access = Access(access | READ);
            break;

        case 'w':
            if (access & WRITE) {
                EnterAndThrow(cx, wrapper, "duplicate 'writable' property flag");
                return false;
            }
            access = Access(access | WRITE);
            break;

        default:
            EnterAndThrow(cx, wrapper, "properties can only be readable or read and writable");
            return false;
        }
    }

    if (access == NO_ACCESS) {
        EnterAndThrow(cx, wrapper, "specified properties must have a permission bit set");
        return false;
    }

    if ((act == Wrapper::SET && !(access & WRITE)) ||
        (act != Wrapper::SET && !(access & READ))) {
        return false;
    }

    return true;
}

bool
ExposedPropertiesOnly::allowNativeCall(JSContext *cx, JS::IsAcceptableThis test,
                                       JS::NativeImpl impl)
{
    return js::IsTypedArrayThisCheck(test);
}

bool
SandboxPolicy::check(JSContext *cx, JSObject *wrapperArg, jsid idArg, Wrapper::Action act)
{
    RootedObject wrapper(cx, wrapperArg);
    RootedId id(cx, idArg);
    RootedObject wrapped(cx, Wrapper::wrappedObject(wrapper));

    bool isPostMessage = false;
    {
        const char *name;
        const js::Class *clasp = js::GetObjectClass(wrapped);
        MOZ_ASSERT(!XrayUtils::IsXPCWNHolderClass(Jsvalify(clasp)), "shouldn't have a holder here");
        if (clasp->ext.innerObject)
            name = "Window";
        else
            name = clasp->name;

        if (JSID_IS_STRING(id))
            isPostMessage = IsPostMessage(name,JSID_TO_FLAT_STRING(id));

#if SWAPI_DEBUG
        printf("SandboxPolicy::check id=%s ", name); 
        if (JSID_IS_STRING(id)) {
        size_t propLength=0;
        const jschar *propChars =
            JS_GetInternedStringCharsAndLength(
                    JS_FORGET_STRING_FLATNESS(JSID_TO_FLAT_STRING(id)),
                    &propLength);
        for (size_t i=0;i<propLength;i++) {
            printf("%c", propChars[i]);
        }
        }
        printf("\n");
#endif
    }


    // Information flows from the wrapped to the wrapper
    // The two are swapped for postMessage
    JSCompartment *fromCompartment = isPostMessage 
                                     ? js::GetObjectCompartment(wrapper)
                                     : js::GetObjectCompartment(wrapped),
                  *toCompartment   = isPostMessage 
                                     ? js::GetObjectCompartment(wrapped)
                                     : js::GetObjectCompartment(wrapper);

#if SWAPI_DEBUG
    {
        printf("SandboxPolicy::check %s\n", 
                act == Wrapper::SET ? "SET" :
                act == Wrapper::CALL ? "CALL" : "GET");
        {
            char *origin;
            GetCompartmentPrincipal(fromCompartment)->GetOrigin(&origin);
            printf("SandboxPolicy::check %s ", origin); 
            nsMemory::Free(origin);
        }
        {
            char *origin;
            GetCompartmentPrincipal(toCompartment)->GetOrigin(&origin);
            printf(" to %s\n\n", origin); 
            nsMemory::Free(origin);
        }
    }
#endif


    // neither one is a sandbox
    if (sandbox::IsCompartmentSandboxMode(toCompartment) &&
        sandbox::IsCompartmentSandboxMode(fromCompartment)) {
        // Both compartments are content

        // Is this allowed by same origin policy? If not, do not allow it
        if (!AccessCheck::isCrossOriginAccessPermitted(cx, wrapperArg, 
                                                       idArg, act)) {
            NS_WARNING("Cross origin SOP check failed");
            return false;
        }
    } 

    // Treat addons as trusted
    // TODO: check sanity here
    if (IsAddonSDK(cx, toCompartment) || IsAddonSDK(cx, fromCompartment)) {
        return true;
    }


    if (!isPostMessage 
        && !(sandbox::IsCompartmentSandbox(fromCompartment) && act == Wrapper::GET)) {
        //set or call ==> READ & WRITE with privs of the fromCompartment
        // fromCompartment [=_from toCompartment
        if (sandbox::GuardRead(toCompartment, fromCompartment, true)) {
            // toCompartment [=_from fromCompartment
            bool ok = sandbox::GuardRead(fromCompartment, toCompartment, false);
            if (!ok)
                NS_WARNING("Read/write guard failed");
            return ok;
        }
        NS_WARNING("Read/write guard failed");
        return false;
    } else { // is postMessage, or we're reading from sandbox (thus definitely a read)
        bool ok = sandbox::GuardRead(toCompartment, fromCompartment, 
                                  act == Wrapper::GET);
                // /* useFromCompartmentPrivs = */ !isPostMessage);
        if (!ok)
            NS_WARNING("postMessage read guard failed");
        return ok;
    }

}

} // namespace xpc
