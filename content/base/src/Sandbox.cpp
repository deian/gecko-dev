/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim:set ts=2 sw=2 sts=2 et cindent: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "mozilla/dom/Sandbox.h"
#include "mozilla/dom/RoleBinding.h"
#include "mozilla/dom/LabelBinding.h"
#include "mozilla/dom/PrivilegeBinding.h"
#include "mozilla/dom/SandboxBinding.h"
#include "nsContentUtils.h"
#include "nsIContentSecurityPolicy.h"
#include "mozilla/EventDispatcher.h"
#include "xpcprivate.h"
#include "xpccomponents.h"
#include "mozilla/dom/StructuredCloneUtils.h"
#include "nsIXMLHttpRequest.h"
#include "nsXMLHttpRequest.h"
#include "mozilla/scache/StartupCache.h"

using namespace JS;
using namespace xpc;

namespace mozilla {
namespace dom {

#define SANDBOX_CONFIG(compartment) \
  xpc::EnsureCompartmentPrivate((compartment))->sandboxConfig

// Helper for getting JSObject* from GlobalObject (without casting .Get())
static inline JSObject* getGlobalJSObject(const GlobalObject& global);
// Helper for adding fresh principal to privilege ownership list of
// compartment
static void own(JSCompartment *, mozilla::dom::Privilege&);
// Helper for fetching a script from a url; guarding such that the
// fetch does not leak information
static void
GetSourceFromURI(JSContext* cx, const nsAString& aURL, 
                 nsAString& src, ErrorResult& aRv);
//Same as above but returns compiled (and potentially cached script)
static bool
GetScriptFromURI(JSContext* cx, const nsAString& aURL, 
                 JS::MutableHandleScript scriptp, ErrorResult& aRv,
                 bool doCache = false);

////////////////////////////////

// SandboxEventTarget:
//
//
NS_IMPL_CYCLE_COLLECTION_CLASS(SandboxEventTarget)

NS_IMPL_CYCLE_COLLECTION_TRAVERSE_BEGIN_INHERITED(SandboxEventTarget,
                                                  DOMEventTargetHelper)
  NS_IMPL_CYCLE_COLLECTION_TRAVERSE_SCRIPT_OBJECTS
NS_IMPL_CYCLE_COLLECTION_TRAVERSE_END

NS_IMPL_CYCLE_COLLECTION_UNLINK_BEGIN_INHERITED(SandboxEventTarget,
                                                DOMEventTargetHelper)
  NS_IMPL_CYCLE_COLLECTION_UNLINK_PRESERVED_WRAPPER
NS_IMPL_CYCLE_COLLECTION_UNLINK_END

NS_INTERFACE_MAP_BEGIN_CYCLE_COLLECTION_INHERITED(SandboxEventTarget)
  NS_WRAPPERCACHE_INTERFACE_MAP_ENTRY
NS_INTERFACE_MAP_END_INHERITING(DOMEventTargetHelper)

NS_IMPL_ADDREF_INHERITED(SandboxEventTarget, DOMEventTargetHelper)
NS_IMPL_RELEASE_INHERITED(SandboxEventTarget, DOMEventTargetHelper)


// Sandbox:

NS_IMPL_CYCLE_COLLECTION_CLASS(Sandbox)

NS_IMPL_CYCLE_COLLECTION_TRAVERSE_BEGIN_INHERITED(Sandbox,
                                                  DOMEventTargetHelper)
  NS_IMPL_CYCLE_COLLECTION_TRAVERSE(mPrivacy)
  NS_IMPL_CYCLE_COLLECTION_TRAVERSE(mTrust)
  NS_IMPL_CYCLE_COLLECTION_TRAVERSE(mCurrentPrivacy)
  NS_IMPL_CYCLE_COLLECTION_TRAVERSE(mCurrentTrust)
  NS_IMPL_CYCLE_COLLECTION_TRAVERSE(mPrincipal)
  NS_IMPL_CYCLE_COLLECTION_TRAVERSE(mEventTarget)
  NS_IMPL_CYCLE_COLLECTION_TRAVERSE_SCRIPT_OBJECTS
NS_IMPL_CYCLE_COLLECTION_TRAVERSE_END

NS_IMPL_CYCLE_COLLECTION_UNLINK_BEGIN_INHERITED(Sandbox,
                                                DOMEventTargetHelper)
  tmp->Destroy();
  NS_IMPL_CYCLE_COLLECTION_UNLINK(mPrivacy)
  NS_IMPL_CYCLE_COLLECTION_UNLINK(mTrust)
  NS_IMPL_CYCLE_COLLECTION_UNLINK(mCurrentPrivacy)
  NS_IMPL_CYCLE_COLLECTION_UNLINK(mCurrentTrust)
  NS_IMPL_CYCLE_COLLECTION_UNLINK(mPrincipal)
  NS_IMPL_CYCLE_COLLECTION_UNLINK(mEventTarget)
  NS_IMPL_CYCLE_COLLECTION_UNLINK_PRESERVED_WRAPPER
NS_IMPL_CYCLE_COLLECTION_UNLINK_END

NS_IMPL_CYCLE_COLLECTION_TRACE_BEGIN_INHERITED(Sandbox,
                                               DOMEventTargetHelper)
  NS_IMPL_CYCLE_COLLECTION_TRACE_PRESERVED_WRAPPER
  NS_IMPL_CYCLE_COLLECTION_TRACE_JS_MEMBER_CALLBACK(mSandboxObj)
  NS_IMPL_CYCLE_COLLECTION_TRACE_JSVAL_MEMBER_CALLBACK(mResult)
  NS_IMPL_CYCLE_COLLECTION_TRACE_JSVAL_MEMBER_CALLBACK(mMessage)
NS_IMPL_CYCLE_COLLECTION_TRACE_END

NS_INTERFACE_MAP_BEGIN_CYCLE_COLLECTION_INHERITED(Sandbox)
  NS_WRAPPERCACHE_INTERFACE_MAP_ENTRY
NS_INTERFACE_MAP_END_INHERITING(DOMEventTargetHelper)

NS_IMPL_ADDREF_INHERITED(Sandbox, DOMEventTargetHelper)
NS_IMPL_RELEASE_INHERITED(Sandbox, DOMEventTargetHelper)

////////////////////////////////

Sandbox::Sandbox(mozilla::dom::Label& privacy, mozilla::dom::Label& trust)
  : mPrivacy(&privacy)
  , mTrust(&trust)
  , mCurrentPrivacy(nullptr)
  , mCurrentTrust(nullptr)
  , mSandboxObj(nullptr)
  , mPrincipal(nullptr)
  , mResult(JSVAL_VOID)
  , mResultType(ResultNone)
  , mEventTarget(new SandboxEventTarget())
  , mMessage(JSVAL_VOID)
  , mMessageIsSet(false)
{
  SetIsDOMBinding();
}

Sandbox::~Sandbox()
{
  mozilla::DropJSObjects(this);
}


void
Sandbox::Destroy()
{
  mPrivacy = nullptr;
  mTrust = nullptr;
  mCurrentPrivacy = nullptr;
  mCurrentTrust = nullptr;
  mSandboxObj = nullptr;
  mPrincipal = nullptr;
  mResult = JSVAL_VOID;
  mEventTarget = nullptr;
  mMessage = JSVAL_VOID;
  mozilla::DropJSObjects(this);
}

already_AddRefed<Sandbox>
Sandbox::Constructor(const GlobalObject& global, 
                     JSContext* cx, ErrorResult& aRv)
{
  aRv.MightThrowJSException();
  EnableSandbox(global, cx);

  nsRefPtr<Label> privacy = GetPrivacyLabel(global, cx);
  if (!privacy) {
    JSErrorResult(cx, aRv, "Failed to get current privacy label.");
    return nullptr;
  }

  nsRefPtr<Label> trust = GetTrustLabel(global, cx);
  if (!trust) {
    JSErrorResult(cx, aRv, "Failed to get current trust label.");
    return nullptr;
  }

  return Constructor(global, cx, *privacy, *trust, aRv);
}

already_AddRefed<Sandbox>
Sandbox::Constructor(const GlobalObject& global,
                     JSContext* cx, 
                     mozilla::dom::Label& privacy, 
                     ErrorResult& aRv)
{
  aRv.MightThrowJSException();
  EnableSandbox(global, cx);

  nsRefPtr<Label> trust = GetTrustLabel(global, cx);
  if (!trust) {
    JSErrorResult(cx, aRv, "Failed to get current trust label.");
    return nullptr;
  }

  return Constructor(global, cx, privacy, *trust, aRv);
}

already_AddRefed<Sandbox>
Sandbox::Constructor(const GlobalObject& global, 
                     JSContext* cx, 
                     mozilla::dom::Label& privacy, 
                     mozilla::dom::Label& trust, 
                     ErrorResult& aRv)
{
  EnableSandbox(global, cx);
  nsRefPtr<Label> privacyCopy = privacy.Clone(aRv);
  if (aRv.Failed()) {
    return nullptr;
  }
  nsRefPtr<Label> trustCopy = trust.Clone(aRv);
  if (aRv.Failed()) {
    return nullptr;
  }

  nsRefPtr<Sandbox> sandbox = new Sandbox(*privacyCopy, *trustCopy);
  if (!sandbox) {
    aRv = NS_ERROR_OUT_OF_MEMORY;
    return nullptr;
  }

  sandbox->Init(global, cx, aRv);

  return sandbox.forget();
}

void
Sandbox::Schedule(JSContext* cx, const nsAString& source, ErrorResult& aRv)
{
  aRv.MightThrowJSException();

  // Compile script
  JS::CompileOptions options(cx);
  options.setFileAndLine("x-bogus://Sandbox",1)
         .setVersion(JSVERSION_DEFAULT)
         .setNoScriptRval(true);

  JS::RootedScript script(cx);
  script = JS::Compile(cx, JS::NullPtr(), options, 
                       NS_ConvertUTF16toUTF8(source).get(), source.Length());
  if (!script) {
    JSErrorResult(cx, aRv, "Failed to compile script");
    return;
  }

  // Schedule it
  Schedule(cx, script, aRv);
}

void
Sandbox::Schedule(JSContext* cx, JS::HandleScript src, ErrorResult& aRv)
{
  aRv.MightThrowJSException();
  JSCompartment *compartment = js::GetContextCompartment(cx);
  nsRefPtr<Label> privs = xpc::sandbox::GetCompartmentPrivileges(compartment);

  MOZ_ASSERT(privs);

  nsRefPtr<Label> callerP =
    xpc::sandbox::GetCompartmentPrivacyLabel(compartment);
  nsRefPtr<Label> callerT =
    xpc::sandbox::GetCompartmentTrustLabel(compartment);

  if (MOZ_UNLIKELY(!xpc::sandbox::IsCompartmentSandboxed(compartment))) {
    //If we somehow ended up with a Sandbox object but are not in a 
    //compartment that is not a sandbox/sandbox-mode

    // enable sandbox-mode
    xpc::sandbox::EnableCompartmentSandbox(compartment);

    //set the initial label of the sandbox to this compartments labels
    callerP = xpc::sandbox::GetCompartmentPrivacyLabel(compartment);
    callerT = xpc::sandbox::GetCompartmentTrustLabel(compartment);
    if (!callerP || !callerT) {
      JSErrorResult(cx, aRv, "Cannot enable sandbox mode");
      return;
    }
  }

  // if this is the first time we're scheduling code in the sandbox,
  // start with an initial label set to the current compartment's
  // labels (though we must check that these labels flow to the labels
  // of the sandbox)
  if (!mCurrentPrivacy && !mCurrentTrust) {
    mCurrentPrivacy = callerP->Clone(aRv);
    if (aRv.Failed()) {
      JSErrorResult(cx, aRv, "Cannot set initial privacy label");
      return;
    }
    mCurrentTrust = callerT->Clone(aRv);
    if (aRv.Failed()) {
      JSErrorResult(cx, aRv, "Cannot set initial trust label");
      return;
    }
  }

  // current compartment label must flow to label of sandbox
  if (!mPrivacy->Subsumes(*privs, *callerP) ||
      !callerT->Subsumes(*privs, *mTrust)) {
    JSErrorResult(cx, aRv, "Cannot execute code in a less sensitive sandbox");
    return;
  }

  // It is required that EvalInSandbox not raise the current labels
  // above the sandbox labels; otherwise we must perform an additional
  // check as the first step in the sandbox

  EvalInSandbox(cx, src,aRv);
}

#define JSERR_ENSURE_SUCCESS(rv, msg)   \
  if (NS_FAILED((rv))) {                \
    JSErrorResult(cx, aRv, (msg));      \
    return;                             \
  }

// TODO: make async
void
GetSourceFromURI(JSContext* cx, const nsAString& aURL, 
                 nsAString& src, ErrorResult& aRv)
{
  aRv.MightThrowJSException();
  nsresult rv;

  nsCOMPtr<nsIPrincipal> urlPrincipal;
  {

    JSCompartment *compartment = js::GetContextCompartment(cx);
    MOZ_ASSERT(compartment);

    // Check that the compartment label+privs [= uri
    nsRefPtr<Label> privs = xpc::sandbox::GetCompartmentPrivileges(compartment);
    if (!privs) 
      privs = new Label();

    nsRefPtr<Label> currentLabel =
      xpc::sandbox::GetCompartmentPrivacyLabel(compartment);
    if (!currentLabel) {
      JSErrorResult(cx, aRv, "Failed to get current privacy label.");
      return;
    }

    // Create URI corresponding to aURL
    nsCOMPtr<nsIURI> uri;
    rv = NS_NewURI(getter_AddRefs(uri), aURL);
    JSERR_ENSURE_SUCCESS(rv, "Couldn't create nsIURI instance from URL");

    bool ishttp=false, ishttps=false;
    uri->SchemeIs("http",&ishttp);
    uri->SchemeIs("https",&ishttps);
    if (!ishttp && !ishttps) {
      JSErrorResult(cx, aRv, "Scheme must be http or https.");
      return;
    }

    nsCOMPtr<nsIScriptSecurityManager> secMan =
      nsContentUtils::GetSecurityManager();
    JSERR_ENSURE_SUCCESS(rv, "Couldn't get script security manager.");

    rv = secMan->GetNoAppCodebasePrincipal(uri, getter_AddRefs(urlPrincipal));
    JSERR_ENSURE_SUCCESS(rv, "Couldn't make principal from URL.");

    nsRefPtr<Role> urlRole = new Role(aURL, aRv);
    if (aRv.Failed()) return;
    nsRefPtr<Label> urlLabel = new Label(*urlRole, aRv);
    if (aRv.Failed()) return;

    // this is privacy so the [= corresponds to <=
    if (!urlLabel->Subsumes(*privs, *currentLabel)) {
      JSErrorResult(cx, aRv, "Fetching script would leak information.");
      return;
    }


  }

  { // Get script from URL
    // TODO: do it async
    nsCOMPtr<nsIXMLHttpRequest> xhr =
      do_CreateInstance(NS_XMLHTTPREQUEST_CONTRACTID, &rv);
    JSERR_ENSURE_SUCCESS(rv, "Couldn't create nsIXMLHttpRequest instance");

    static_cast<nsXMLHttpRequest*>(xhr.get())->SetParameters(/*aAnon=*/true,
                                                             /*aSystem=*/false);

    NS_NAMED_LITERAL_CSTRING(getString, "GET");
    const nsAString& empty = EmptyString();


    rv = xhr->Init(urlPrincipal, nullptr, nullptr, nullptr);
    JSERR_ENSURE_SUCCESS(rv, "Couldn't initialize the XHR");

    rv = xhr->Open(getString, NS_ConvertUTF16toUTF8(aURL),
        false, empty, empty);
    JSERR_ENSURE_SUCCESS(rv, "OpenRequest failed");

    rv = xhr->Send(nullptr);
    JSERR_ENSURE_SUCCESS(rv, "Send failed");

    rv = xhr->GetResponseText(src);
    JSERR_ENSURE_SUCCESS(rv, "GetResponse failed");
  }

}

bool
GetScriptFromURI(JSContext* cx, const nsAString& aURL, 
                 JS::MutableHandleScript scriptp, ErrorResult& aRv,
                 bool doCache)
{
  aRv.MightThrowJSException();
  const char *filename = NS_ConvertUTF16toUTF8(aURL).get();
  scache::StartupCache* cache = doCache ? scache::StartupCache::GetSingleton()
                                        : nullptr;

  if (cache) {
    // Fetch script from cache
    nsAutoArrayPtr<char> buf;
    uint32_t len = 0;

    if (NS_SUCCEEDED(cache->GetBuffer(filename, getter_Transfers(buf), &len))) {
      scriptp.set(JS_DecodeScript(cx, buf, len, nullptr));
      // If the decoding is ok, return early
      if (scriptp) {
        return true;
      } 
    }
  } 

  if (!scriptp) {
    nsAutoString source;
    // Fetch source
    GetSourceFromURI(cx, aURL, source, aRv);
    if (aRv.Failed()) {
      return false;
    }

    // Compile script
    JS::CompileOptions options(cx);
    options.setFileAndLine(filename, 1)
           .setNoScriptRval(true);
    scriptp.set(JS::Compile(cx, JS::NullPtr(), options, 
                            NS_ConvertUTF16toUTF8(source).get(), source.Length()));

    if (cache) {
      // Cache script
      uint32_t size;
      void *data = JS_EncodeScript(cx, scriptp, &size);
      if (data) {
        MOZ_ASSERT(size);
        cache->PutBuffer(filename, static_cast<char *>(data), size);
        js_free(data);
      }
    }
  }

  // By this point we should have a compiled script

  if (!scriptp) {
    JSErrorResult(cx, aRv, "Failed to fetch/compile script");
  }

  return false;
}

void
Sandbox::ScheduleURI(JSContext* cx, const nsAString& aURL, 
                     const Optional<bool>& aCache, ErrorResult& aRv)
{
  bool doCache = aCache.WasPassed() ? aCache.Value() : false;

  JS::RootedScript script(cx);

  GetScriptFromURI(cx, aURL, &script, aRv, doCache);

  if (!aRv.Failed())
    Schedule(cx, script, aRv);

}
#undef JSERR_ENSURE_SUCCESS


bool
Sandbox::IsClean() const
{
  return !mCurrentPrivacy && !mCurrentTrust;
}

void 
Sandbox::Ondone(JSContext* cx, EventHandlerNonNull* successHandler, 
                const Optional<nsRefPtr<EventHandlerNonNull> >& errorHandler,
                ErrorResult& aRv)
{
  aRv.MightThrowJSException();

  JSCompartment *compartment = js::GetContextCompartment(cx);
  MOZ_ASSERT(compartment);


  if (MOZ_UNLIKELY(!xpc::sandbox::IsCompartmentSandboxed(compartment)))
    xpc::sandbox::EnableCompartmentSandbox(compartment);

  nsRefPtr<Label> privs = xpc::sandbox::GetCompartmentPrivileges(compartment);
  
  // raises current label
  if (!xpc::sandbox::GuardRead(compartment, *mPrivacy,*mTrust,
                               privs, cx, true)) {
    JSErrorResult(cx, aRv, "Cannot read from sandbox.");
    return;
  }

  // set handlers

  SetOnmessage(successHandler);

  if (errorHandler.WasPassed()) {
    SetOnerror(errorHandler.Value());
  }

  //dispatch handlers

  if (!DispatchResult(cx))
    aRv.Throw(NS_ERROR_FAILURE);
}

void
Sandbox::PostMessage(JSContext* cx, JS::Handle<JS::Value> message, 
                     ErrorResult& aRv)
{
  aRv.MightThrowJSException();

  // check that we can write to sandbox, but fail silently
  if (!GuardWriteOnly(cx)) return;

  // clear message
  ClearMessage();

  // Structurally clone the object
  JS::RootedValue v(cx, message);

  // Apply the structured clone algorithm
  StructuredCloneData data;
  JSAutoStructuredCloneBuffer buffer;

  if (!WriteStructuredClone(cx, v, buffer, data.mClosure)) {
    JSErrorResult(cx, aRv,
        "postMessage: Argument must be a structurally clonable object.");
    return;
  } 

  {
    // enter sandbox compartment
    JS::RootedObject sandboxObj(cx, js::UncheckedUnwrap(mSandboxObj));
    JSAutoRequest req(cx);
    JSAutoCompartment ac(cx, sandboxObj);

    data.mData       = buffer.data();
    data.mDataLength = buffer.nbytes();

    MOZ_ASSERT(ReadStructuredClone(cx, data, &v)); // buffer->object

    // Set the message
    SetMessage(v);

    // Dispatch event to the sandbox onmessage handler
    DispatchSandboxOnmessageEvent(aRv);
  }
}

void
Sandbox::DispatchSandboxOnmessageEvent(ErrorResult& aRv)
{
  if (!mMessageIsSet) return;

  nsCOMPtr<nsIDOMEvent> event;
  nsresult rv = EventDispatcher::CreateEvent(mEventTarget, nullptr, nullptr,
                                             NS_LITERAL_STRING("Events"),
                                             getter_AddRefs(event));
  if (NS_FAILED(rv)) {
    aRv.Throw(rv);
    return;
  }

  event->InitEvent(NS_LITERAL_STRING("message"), 
                   /* canBubble = */ false,
                   /* canCancel = */ false);
  event->SetTrusted(true);

  mEventTarget->DispatchDOMEvent(nullptr, event, nullptr, nullptr);
}

already_AddRefed<Label>
Sandbox::Privacy() const
{
  nsRefPtr<Label> privacy = mPrivacy;
  return privacy.forget();
}

already_AddRefed<Label>
Sandbox::Trust() const
{
  nsRefPtr<Label> trust = mTrust;
  return trust.forget();
}

already_AddRefed<Label>
Sandbox::CurrentPrivacy() const
{
  nsRefPtr<Label> privacy = mCurrentPrivacy;
  return privacy.forget();
}

// Caller should ensure that this label subsumes the current label and
// is subsumed by the sanbox label
void 
Sandbox::SetCurrentPrivacy(mozilla::dom::Label* aLabel)
{
  mCurrentPrivacy = aLabel;
}

already_AddRefed<Label>
Sandbox::CurrentTrust() const
{
  nsRefPtr<Label> trust = mCurrentTrust;
  return trust.forget();
}

// Caller should ensure that this label subsumes the sandbox label and
// is subsumed by the current label
void
Sandbox::SetCurrentTrust(mozilla::dom::Label* aLabel) 
{
  mCurrentTrust = aLabel;
}


JS::Value
Sandbox::GetResult(JSContext* cx, ErrorResult& aRv) {
  aRv.MightThrowJSException();

  {
    //TODO: reduce copy-paste shared with OnDone
    JSCompartment *compartment = js::GetContextCompartment(cx);
    MOZ_ASSERT(compartment);


    if (MOZ_UNLIKELY(!xpc::sandbox::IsCompartmentSandboxed(compartment)))
      xpc::sandbox::EnableCompartmentSandbox(compartment);

    nsRefPtr<Label> privs = xpc::sandbox::GetCompartmentPrivileges(compartment);

    // raises current label
    if (!xpc::sandbox::GuardRead(compartment, *mPrivacy,*mTrust,
          privs, cx, true)) {
      JSErrorResult(cx, aRv, "Cannot read from sandbox.");
      return JSVAL_VOID;
    }
  }

  
  JS::RootedValue v(cx, mResult);

  if (!JS_WrapValue(cx, &v)) {
    JSErrorResult(cx, aRv, "Failed to wrap message.");
    return JSVAL_VOID;
  }

  return v;
}

// Returns true if writing to the sandbox is allowerd
// I.e. the current label flows to the label of the sandbox
bool
Sandbox::GuardWriteOnly(JSContext* cx) const {
  JSCompartment* compartment = js::GetContextCompartment(cx);
  MOZ_ASSERT(compartment);

  nsRefPtr<Label> curPrivs   =
    xpc::sandbox::GetCompartmentPrivileges(compartment);

  return xpc::sandbox::GuardWrite(compartment, *mPrivacy, *mTrust, curPrivs);
}

void 
Sandbox::Grant(JSContext* cx, mozilla::dom::Privilege& priv)
{
  //TODO change to a grant/ongrant API

  // check that we can write to sandbox, but fail silently
  if (!GuardWriteOnly(cx)) return;

  // get the unwrapped sandbox object and enter its compartment
  JSCompartment* sandboxCompartment = 
    js::GetObjectCompartment(js::UncheckedUnwrap(mSandboxObj));

  // Take ownership
  // TODO: Again, once we move to a grant/ongrant API we let the
  // sandbox decide whether it wants to have these privileges or not.

  // own clones the underlying privilege
  own(sandboxCompartment, priv);
}

void 
Sandbox::AttachObject(JSContext* cx, JS::Handle<JSObject*> aObj,
                      const nsAString& name, ErrorResult& aRv)
{
  aRv.MightThrowJSException();

  // check that we can write to sandbox, but fail silently
  if (!GuardWriteOnly(cx)) return;

  // unwrap the object
//  JS::RootedObject obj(cx, js::UncheckedUnwrap(aObj));

  {
    // enter sandbox compartment
    JS::RootedObject sandboxObj(cx, js::UncheckedUnwrap(mSandboxObj));
    JSAutoRequest req(cx);
    JSAutoCompartment ac(cx, sandboxObj);

    JS::RootedObject obj(cx, js::UncheckedUnwrap(aObj));

    // wrap the object
    if (!JS_WrapObject(cx, &obj)) {
      JSErrorResult(cx, aRv, "Failed to wrap object.");
      return;
    }

    JS::RootedString objName(cx, 
        JS_NewStringCopyZ(cx, ToNewUTF8String(name)));
    JS::RootedId id(cx);
    if (!JS_StringToId(cx, objName , &id)) {
      JSErrorResult(cx, aRv, "Failed to map name to id");
      return;
    }

    if (!JS_DefinePropertyById(cx, sandboxObj, id, JS::ObjectValue(*obj),
                               JS_PropertyStub, JS_StrictPropertyStub,
                               JSPROP_ENUMERATE)) {
      JSErrorResult(cx, aRv, "Failed to attach object to sandbox.");
      return;
    }
  }
}

inline void
Sandbox::SetResult(JS::Handle<JS::Value> val, ResultType type)
{
  mResult = val;
  mResultType = type;
  mozilla::HoldJSObjects(this);
}

inline void
Sandbox::ClearResult()
{
  mResult = JSVAL_VOID;
  mResultType = ResultNone;
//  mozilla::HoldJSObjects(this);
}

inline void
Sandbox::SetMessage(JS::Handle<JS::Value> val)
{
  mMessage = val;
  mozilla::HoldJSObjects(this);
  mMessageIsSet = true;
}

inline void
Sandbox::ClearMessage()
{
  mMessage = JSVAL_VOID;
  mMessageIsSet = false;
  //mozilla::HoldJSObjects(this);
}


bool
Sandbox::SetMessageToHandle(JSContext *cx, JS::MutableHandleValue vp)
{
  // Wrap the message
  /*
  if (!JS_WrapValue(cx, mMessage.unsafeGet())) {
    ClearMessage();
    JS_ReportError(cx, "Failed to wrap message.");
    return false;
  }
  */
  vp.set(mMessage);
  return true;
}


// Static ====================================================================

void
Sandbox::EnableSandbox(const GlobalObject& global, JSContext *cx)
{
  if (IsSandboxed(global)) return;

  JSCompartment *compartment =
    js::GetObjectCompartment(getGlobalJSObject(global));
  MOZ_ASSERT(compartment);
  xpc::sandbox::EnableCompartmentSandbox(compartment);

  /*
  if (IsSandboxMode(global))
    js::RecomputeWrappers(cx, js::AllCompartments(), js::AllCompartments());
  */
}

bool 
Sandbox::IsSandboxed(const GlobalObject& global)
{
  JSCompartment *compartment =
    js::GetObjectCompartment(getGlobalJSObject(global));
  MOZ_ASSERT(compartment);
  return xpc::sandbox::IsCompartmentSandboxed(compartment);
}

bool 
Sandbox::IsSandbox(const GlobalObject& global)
{
  JSCompartment *compartment =
    js::GetObjectCompartment(getGlobalJSObject(global));
  MOZ_ASSERT(compartment);
  return xpc::sandbox::IsCompartmentSandbox(compartment);
}

bool 
Sandbox::IsSandboxMode(const GlobalObject& global)
{
  JSCompartment *compartment =
    js::GetObjectCompartment(getGlobalJSObject(global));
  MOZ_ASSERT(compartment);
  return xpc::sandbox::IsCompartmentSandboxMode(compartment);
}

// label

void
Sandbox::SetPrivacyLabel(const GlobalObject& global, JSContext* cx, 
                         mozilla::dom::Label& aLabel, ErrorResult& aRv)
{
  aRv.MightThrowJSException();
  EnableSandbox(global, cx);

  JSCompartment *compartment =
    js::GetObjectCompartment(getGlobalJSObject(global));
  MOZ_ASSERT(compartment);


  nsRefPtr<Label> privs = xpc::sandbox::GetCompartmentPrivileges(compartment);

  nsRefPtr<Label> currentLabel = GetPrivacyLabel(global, cx);
  if (!currentLabel) {
    JSErrorResult(cx, aRv, "Failed to get current privacy label.");
    return;
  }

  if (!aLabel.Subsumes(*privs, *currentLabel)) {
    JSErrorResult(cx, aRv, "Label is not above the current label.");
    return;
  }

  nsRefPtr<Label> currentClearance = GetPrivacyClearance(global, cx);
  if (currentClearance && !currentClearance->Subsumes(aLabel)) {
    JSErrorResult(cx, aRv, "Label is not below the current clearance.");
    return;
  }

  xpc::sandbox::SetCompartmentPrivacyLabel(compartment, &aLabel);
  //RecomputeWrappers called by RefineSecurityPerimeter
  if (IsSandboxMode(global)) {
    xpc::sandbox::RefineCompartmentSandboxPolicies(compartment, cx);
  }
}

// Helper macro for retriveing the privacy/trust label/clearance
#define GET_LABEL(name)                                                   \
  do {                                                                    \
    JSCompartment *compartment =                                          \
      js::GetObjectCompartment(getGlobalJSObject(global));                \
    MOZ_ASSERT(compartment);                                              \
    nsRefPtr<Label> l = xpc::sandbox::GetCompartment##name(compartment);  \
                                                                          \
    if (!l) return nullptr;                                               \
    return l.forget();                                                    \
  } while(0);

already_AddRefed<Label>
Sandbox::GetPrivacyLabel(const GlobalObject& global, JSContext* cx)
{
  EnableSandbox(global, cx);
  GET_LABEL(PrivacyLabel);
}

void
Sandbox::SetTrustLabel(const GlobalObject& global, JSContext* cx, 
              mozilla::dom::Label& aLabel, ErrorResult& aRv)
{
  aRv.MightThrowJSException();
  EnableSandbox(global, cx);

  JSCompartment *compartment =
    js::GetObjectCompartment(getGlobalJSObject(global));
  MOZ_ASSERT(compartment);

  nsRefPtr<Label> privs = xpc::sandbox::GetCompartmentPrivileges(compartment);

  nsRefPtr<Label> currentLabel = GetTrustLabel(global, cx);
  if (!currentLabel) {
    JSErrorResult(cx, aRv, "Failed to get current trust label.");
    return;
  }

  if (!currentLabel->Subsumes(*privs, aLabel)) {
    JSErrorResult(cx, aRv, "Label is not below the current label.");
    return;
  }

  nsRefPtr<Label> currentClearance = GetTrustClearance(global, cx);
  if (currentClearance && !aLabel.Subsumes(*currentClearance)) {
    JSErrorResult(cx, aRv, "Label is not above the current clearance.");
    return;
  }

  xpc::sandbox::SetCompartmentTrustLabel(compartment, &aLabel);
  js::RecomputeWrappers(cx, js::AllCompartments(), js::AllCompartments());

}

already_AddRefed<Label>
Sandbox::GetTrustLabel(const GlobalObject& global, JSContext* cx)
{
  EnableSandbox(global, cx);
  GET_LABEL(TrustLabel);
}

//clearance

void
Sandbox::SetPrivacyClearance(const GlobalObject& global, JSContext* cx, 
                             mozilla::dom::Label& aLabel, ErrorResult& aRv)
{
  aRv.MightThrowJSException();
  EnableSandbox(global, cx);

  if (!IsSandboxMode(global)) {
    JSErrorResult(cx, aRv, 
                  "Can only set the clearance in a sandbox-mode compartment.");
    return;
  }

  JSCompartment *compartment =
    js::GetObjectCompartment(getGlobalJSObject(global));
  MOZ_ASSERT(compartment);

  nsRefPtr<Label> privs = xpc::sandbox::GetCompartmentPrivileges(compartment);

  nsRefPtr<Label> currentClearance = GetPrivacyClearance(global, cx);
  if (currentClearance && !currentClearance->Subsumes(*privs, aLabel)) {
    JSErrorResult(cx, aRv, "Clearance is not below the current clearance.");
    return;
  }

  nsRefPtr<Label> currentLabel = GetPrivacyLabel(global, cx);
  if (!currentLabel) {
    JSErrorResult(cx, aRv, "Failed to get current trust label.");
    return;
  }

  if (!aLabel.Subsumes(*currentLabel)) {
    JSErrorResult(cx, aRv, "Clearance is not above the current label.");
    return;
  }

  xpc::sandbox::SetCompartmentPrivacyClearance(compartment, &aLabel);
}

already_AddRefed<Label>
Sandbox::GetPrivacyClearance(const GlobalObject& global, JSContext* cx)
{
  EnableSandbox(global, cx);
  GET_LABEL(PrivacyClearance);
}

void
Sandbox::SetTrustClearance(const GlobalObject& global, JSContext* cx, 
                           mozilla::dom::Label& aLabel, ErrorResult& aRv)
{
  aRv.MightThrowJSException();
  EnableSandbox(global, cx);

  if (!IsSandboxMode(global)) {
    JSErrorResult(cx, aRv,
                  "Can only set the clearance in a sandbox-mode compartment.");
    return;
  }

  JSCompartment *compartment =
    js::GetObjectCompartment(getGlobalJSObject(global));
  MOZ_ASSERT(compartment);

  nsRefPtr<Label> privs = xpc::sandbox::GetCompartmentPrivileges(compartment);

  nsRefPtr<Label> currentClearance = GetTrustClearance(global, cx);
  if (currentClearance && !aLabel.Subsumes(*privs, *currentClearance)) {
    JSErrorResult(cx, aRv, "Clearance is not above the current clearance.");
    return;
  }

  nsRefPtr<Label> currentLabel = GetTrustLabel(global, cx);
  if (!currentLabel) {
    JSErrorResult(cx, aRv, "Failed to get current trust label.");
    return;
  }

  if (!currentLabel->Subsumes(aLabel)) {
    JSErrorResult(cx, aRv, "Clearance is not below the current label.");
    return;
  }

  xpc::sandbox::SetCompartmentTrustClearance(compartment, &aLabel);
}

already_AddRefed<Label>
Sandbox::GetTrustClearance(const GlobalObject& global, JSContext* cx)
{
  EnableSandbox(global, cx);
  GET_LABEL(TrustClearance);
}

#undef GET_LABEL

// Get underlying privileges
already_AddRefed<Privilege>
Sandbox::Privileges(const GlobalObject& global, JSContext* cx)
{
  EnableSandbox(global, cx);

  JSCompartment *compartment =
    js::GetObjectCompartment(getGlobalJSObject(global));
  MOZ_ASSERT(compartment);

  // copy compartment privileges
  nsRefPtr<Label> privL =
    xpc::sandbox::GetCompartmentPrivileges(compartment);

  nsRefPtr<Privilege> privs;

  if (!privL) 
    return nullptr;

  privs = new Privilege(*privL);

  return privs.forget();
}

void 
Sandbox::SetPrivileges(const GlobalObject& global, JSContext* cx,
                       mozilla::dom::Privilege& priv, ErrorResult& aRv)
{
  EnableSandbox(global, cx);
  JSCompartment *compartment =
    js::GetObjectCompartment(getGlobalJSObject(global));
  MOZ_ASSERT(compartment);
  nsRefPtr<Label> newPrivs = priv.GetAsLabel(aRv);
  if (aRv.Failed()) return;
  SANDBOX_CONFIG(compartment).SetPrivileges(newPrivs);
  //RecomputeWrappers called by RefineSecurityPerimeter
  if (IsSandboxMode(global)) {
    xpc::sandbox::RefineCompartmentSandboxPolicies(compartment, cx);
  }
}


// Static ====================================================================


// API exposed to Sandbox ====================================================

static bool
SandboxDone(JSContext *cx, unsigned argc, jsval *vp)
{
  JS::CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 1) {
    JS_ReportError(cx, "Invalid number of arguments.");
    return false;
  }

  // Structurally clone the object

  JS::RootedValue v(cx, args[0]);
  // Apply the structured clone algorithm
  StructuredCloneData data;
  JSAutoStructuredCloneBuffer buffer;

  if (!WriteStructuredClone(cx, v, buffer, data.mClosure)) {
    JS_ReportError(cx,
        "SandboxDone: Argument must be a structurally clonable object.");
    return false;
  }

  data.mData = buffer.data();
  data.mDataLength = buffer.nbytes();

  MOZ_ASSERT(ReadStructuredClone(cx, data, &v)); // buffer->object

  // Set the result in the sandbox

  JSCompartment* compartment = js::GetContextCompartment(cx);
  mozilla::dom::Sandbox* sandbox =
    xpc::sandbox::GetCompartmentSandbox(compartment);

  MOZ_ASSERT(sandbox); // must be in sandboxed compartment

  sandbox->SetResult(v, mozilla::dom::Sandbox::ResultType::ResultValue);

  // Handler may be called after ondone is registered, dispatch
  
  if (!sandbox->DispatchResult(cx)) {
    JS_ReportError(cx, "Failed to dispatch result.");
    return false;
  }


  return true;
}

static bool
SandboxOnmessage(JSContext *cx, unsigned argc, jsval *vp)
{
  // in sandbox:
  JSCompartment* compartment = js::GetContextCompartment(cx);
  mozilla::dom::Sandbox* sandbox =
    xpc::sandbox::GetCompartmentSandbox(compartment);

  MOZ_ASSERT(sandbox); // must be in sandboxed compartment

  // Raise label of sandbox
  sandbox->RaiseLabel();

  // check that the number of arguments is 1
  JS::CallArgs args = CallArgsFromVp(argc, vp);
  if (args.length() != 1) {
    JS_ReportError(cx, "Invalid number of arguments.");
    return false;
  }

  // make sure that the argument is a function
  JS::RootedObject callable(cx);
  if (!args[0].isObject() ||
      !JS_ValueToObject(cx, args[0], &callable) ||
      !JS_ObjectIsCallable(cx, callable)) {
    JS_ReportError(cx, "Argument must be a callable object.");
    return false;
  }

  // use function as an event handler
  nsRefPtr<EventHandlerNonNull> callback = 
    new EventHandlerNonNull(callable, GetIncumbentGlobal());

  if (!callback) {
    JS_ReportError(cx, "Could not convert to handler.");
    return false;
  }

  // set the event handler
  sandbox->SetOnmessageForSandbox(callback);


  // Dispatch event handler
  ErrorResult aRv;
  sandbox->DispatchSandboxOnmessageEvent(aRv);
  if (aRv.Failed()) {
    JS_ReportError(cx, "Could not dispatch onmessage.");
    return false;
  }
  return true;
}

static bool
SandboxGetMessage(JSContext *cx, JS::HandleObject obj, JS::HandleId id,
                  JS::MutableHandleValue vp)
{
  // in sandbox:
  JSCompartment* compartment = js::GetContextCompartment(cx);
  mozilla::dom::Sandbox* sandbox =
    xpc::sandbox::GetCompartmentSandbox(compartment);

  MOZ_ASSERT(sandbox); // must be in sandboxed compartment

  // Raise label of sandbox
  sandbox->RaiseLabel();

  return sandbox->SetMessageToHandle(cx, vp);
}

void
Sandbox::GetPrincipal(const GlobalObject& global, JSContext* cx, nsString& retval)
{
  EnableSandbox(global, cx);
  retval = NS_LITERAL_STRING("");
  JSCompartment *compartment =
    js::GetObjectCompartment(getGlobalJSObject(global));
  MOZ_ASSERT(compartment);

  nsIPrincipal* prin = xpc::GetCompartmentPrincipal(compartment);
  if (!prin) return;

  char *origin = NULL;
  if (NS_FAILED(prin->GetOrigin(&origin)))
    return;
  AppendASCIItoUTF16(origin, retval);
  NS_Free(origin);
}

//helper function
static void
own(JSCompartment *compartment, mozilla::dom::Privilege& priv) {
  MOZ_ASSERT(xpc::sandbox::IsCompartmentSandboxed(compartment));
  ErrorResult aRv;
  nsRefPtr<Label> newPrivs = priv.GetAsLabel(aRv);
  MOZ_ASSERT(!aRv.Failed());
  if (aRv.Failed()) return;
  nsRefPtr<Label> curPrivs = SANDBOX_CONFIG(compartment).GetPrivileges();
  curPrivs->_And(*newPrivs, aRv);
}

void
Sandbox::Own(const GlobalObject& global, JSContext* cx,
             mozilla::dom::Privilege& priv)
{
  EnableSandbox(global, cx);
  JSCompartment *compartment =
    js::GetObjectCompartment(getGlobalJSObject(global));
  MOZ_ASSERT(compartment);

  MOZ_ASSERT(compartment);
  own(compartment, priv);
}

void
Sandbox::Import(const GlobalObject& global, JSContext* cx,
                const nsAString& aURL, const Optional<bool>& aCache,
                ErrorResult& aRv)
{
  bool doCache = aCache.WasPassed() ? aCache.Value() : false;
  aRv.MightThrowJSException();
  EnableSandbox(global, cx);

  JS::RootedScript script(cx);
  bool isCached = GetScriptFromURI(cx, aURL, &script, aRv, doCache);


  // Execute script
  JS::RootedObject rootedGlobal(cx, getGlobalJSObject(global));
  bool ok = isCached ? JS::CloneAndExecuteScript(cx, rootedGlobal, script)
                     : JS_ExecuteScript(cx, rootedGlobal, script);

  if (!ok) {
    JSErrorResult(cx, aRv, "Executing script failed");
    return;
  }
}


// Internal ==================================================================


// Set the compartment and current sandbox labels to the sandbox
// label (set at construction time).
void
Sandbox::RaiseLabel()
{
  mCurrentPrivacy = mPrivacy;
  mCurrentTrust = mTrust;
}

// This function tries to dispatch an event. It fails silently if it
// can't dispatch an event due to the result not being set or the
// handlers not being registered.
bool
Sandbox::DispatchResult(JSContext* cx)
{
  // Only dispatch if result has been set
  if (mResultType == ResultNone)
    return true;

  if (!GetOnmessage() || (mResultType == ResultError && !GetOnerror()))
    return true;

  // Wrap the result
  /*
  if (!JS_WrapValue(cx, mResult.unsafeGet())) {
    ClearResult();
    return false;
  }
  */

  nsCOMPtr<nsIDOMEvent> event;
  nsresult rv = EventDispatcher::CreateEvent(this, nullptr, nullptr,
                                             NS_LITERAL_STRING("Events"),
                                             getter_AddRefs(event));
  if (NS_FAILED(rv)) {
    JS_ReportError(cx, "Failed to create event.");
    return false;
  }

  event->InitEvent((mResultType == ResultError) ? NS_LITERAL_STRING("error")
                                                : NS_LITERAL_STRING("message"),
                   /* canBubble = */ false, /* canCancel = */ false);

  event->SetTrusted(true);

  DispatchDOMEvent(nullptr, event, nullptr, nullptr);

  return true;
}

void 
Sandbox::SetOnmessageForSandbox(mozilla::dom::EventHandlerNonNull* aCallback)
{
  mEventTarget->SetOnmessage(aCallback);
}


void
Sandbox::Init(const GlobalObject& global, JSContext* cx, ErrorResult& aRv)
{
  aRv.MightThrowJSException();
  nsresult rv;

  // Set the sandbox principal and add CSP policy that restrict
  // network communication accordingly

  nsCOMPtr<nsIPrincipal> principal = mPrivacy->GetPrincipalIfSingleton();

  // We export the XHR constructor in every case, but CSP only
  // allows 'self' when the privacy label corresponds to the
  // singleton-principal, and '*' when the label is public. 
  // This depends on bug 886164

  if (principal) {
    // Just use principal in label. We don't need
    // to clone it since we do this when we create labels.
    mPrincipal = principal;
  } else {
    mPrincipal = do_CreateInstance("@mozilla.org/nullprincipal;1", &rv);
    if(NS_FAILED(rv)) { aRv.Throw(rv); return; }
  }

  nsString policy;
  if (mPrivacy->IsEmpty()) { // case 1: public label:
    policy = NS_LITERAL_STRING("default-src * 'unsafe-inline'");
  } else if (!principal) {   // case 2: conjunctive label:
    policy = NS_LITERAL_STRING("default-src 'none' 'unsafe-inline';");
  } else {                   // case 3: singleton label:
    policy = NS_LITERAL_STRING("default-src 'none' 'unsafe-inline'; \
                                connect-src 'self';");
  }

  { //set csp policy on principal
    nsCOMPtr<nsIContentSecurityPolicy> csp =
      do_CreateInstance("@mozilla.org/contentsecuritypolicy;1", &rv);
    if(NS_FAILED(rv)) { aRv.Throw(rv); return; }

    nsCOMPtr<nsIURI> uri;
    rv = mPrincipal->GetURI(getter_AddRefs(uri));
    if(NS_FAILED(rv)) { aRv.Throw(rv); return; }

    { // remove any existing policies
      int numPolicies = 0;
      nsresult rv = csp->GetPolicyCount(&numPolicies);
      if (NS_SUCCEEDED(rv)) {
        for (int i=numPolicies-1; i>=0; i--)
          csp->RemovePolicy(i);
      }
    }
    csp->AppendPolicy(policy, uri, false, true);
    rv = mPrincipal->SetCsp(csp);
    if(NS_FAILED(rv)) { aRv.Throw(rv); return; }
  }


  RootedValue sandboxVal(cx, JS::UndefinedValue());
  SandboxOptions sandboxOptions;
  sandboxOptions.sandboxName.AssignASCII("Sandboxed script");
  sandboxOptions.invisibleToDebugger = true;
  sandboxOptions.wantComponents      = false;
  sandboxOptions.wantXrays           = false;
  sandboxOptions.globalProperties.XMLHttpRequest = true;
  rv = CreateSandboxObject(cx, &sandboxVal, mPrincipal, sandboxOptions);
  if (NS_FAILED(rv)) {
    JSErrorResult(cx, aRv, "Failed to create sandbox object");
    return;
  }

  RootedObject sandbox(cx, js::UncheckedUnwrap(&sandboxVal.toObject()));
  if (!sandbox) {
    JSErrorResult(cx, aRv, "Failed to convert sandbox value to object");
    return;
  }


  {
    // Make a special cx for the sandbox and push it.
    // NB: As soon as the RefPtr goes away, the cx goes away. So declare
    // it first so that it disappears last.
    nsRefPtr<xpc::ContextHolder> sandCxHolder = new ContextHolder(cx, sandbox, mPrincipal);
    JSContext *sandcx = sandCxHolder->GetJSContext();
    MOZ_ASSERT(sandcx, "Can't prepare context for evalInSandbox");
    if (!sandcx) {
      JS_ReportError(cx, "Missing sandbox context");
      return;
    }
    nsCxPusher pusher;
    pusher.Push(sandcx);
    JSAutoCompartment ac(sandcx, sandbox);

    mozilla::dom::RoleBinding::GetConstructorObject(sandcx, sandbox);
    mozilla::dom::LabelBinding::GetConstructorObject(sandcx, sandbox);
    mozilla::dom::PrivilegeBinding::GetConstructorObject(sandcx, sandbox);
    mozilla::dom::SandboxBinding::GetConstructorObject(sandcx, sandbox);

    //TODO: check if any of these fail
    JS_DefineFunction(sandcx, sandbox, "done", SandboxDone, 1, 0);
    JS_DefineFunction(sandcx, sandbox, "onmessage", SandboxOnmessage, 1, 0);
    JS_DefineProperty(sandcx, sandbox, "message", 0, 
        JSPROP_ENUMERATE | JSPROP_SHARED, SandboxGetMessage);

    JSCompartment *compartment = js::GetObjectCompartment(sandbox);
    xpc::sandbox::EnableCompartmentSandbox(compartment, this);
  }

  mSandboxObj = sandbox;
  mozilla::HoldJSObjects(this);
}

void
Sandbox::EvalInSandbox(JSContext *cx, JS::HandleScript script, ErrorResult &aRv)
{
  aRv.MightThrowJSException();

  JS_AbortIfWrongThread(JS_GetRuntime(cx));

  // We create a separate cx to do the sandbox evaluation. Scope it.
  RootedValue v(cx, UndefinedValue());
  bool ok = true;
  {
    JS::RootedObject sandboxObj(cx, js::UncheckedUnwrap(mSandboxObj));
    JSAutoRequest req(cx);
    JSAutoCompartment ac(cx, sandboxObj);

    JS::RootedObject rootedSandbox(cx, mSandboxObj);
    ok = JS::CloneAndExecuteScript(cx, rootedSandbox, script);

    // Raise the label of the sandbox compartment to the sandbox label
    RaiseLabel();

    // If the sandbox threw an exception, grab it off the context.
    if (JS_GetPendingException(cx, &v)) {
      MOZ_ASSERT(!ok);
      JS_ClearPendingException(cx);
      SetResult(v, ResultError);
    }
  }

  //
  // Alright, we're back on the caller's cx. If an error occured, try to
  // wrap and set the exception. Otherwise, wrap the return value.
  //

  if (!DispatchResult(cx)) {
    JSErrorResult(cx, aRv, "Failed to dispatch");
  }
}
// Internal ==================================================================

// Helpers ===================================================================

// Helper for getting JSObject* from GlobalObject
JSObject*
getGlobalJSObject(const GlobalObject& global)
{
  return global.Get();
}

// Helper for setting the ErrorResult to a string.  This function
// should only be called after MightThrowJSException() is called.
void
JSErrorResult(JSContext *cx, ErrorResult& aRv, const char *msg)
{
  JSString *err = JS_NewStringCopyZ(cx,msg); 
  if (err) {
    JS::RootedValue errv(cx, STRING_TO_JSVAL(err));
    aRv.ThrowJSException(cx,errv);
  } else {
    aRv.Throw(NS_ERROR_OUT_OF_MEMORY);
  }
}

// Helpers ===================================================================

#undef SANDBOX_CONFIG
} // namespace dom
} // namespace mozilla
