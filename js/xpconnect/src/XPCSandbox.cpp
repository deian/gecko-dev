/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim:set ts=2 sw=2 sts=2 et cindent: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "mozilla/Assertions.h"
#include "xpcprivate.h"
#include "xpcpublic.h"
#include "jsfriendapi.h"
#include "mozilla/dom/Sandbox.h"
#include "mozilla/dom/Label.h"
#include "mozilla/dom/Role.h"
#include "nsIContentSecurityPolicy.h"
#include "nsDocument.h"

using namespace xpc;
using namespace JS;
using namespace mozilla;
using namespace mozilla::dom;

namespace xpc {
namespace sandbox {

#define SANDBOX_CONFIG(compartment) \
    EnsureCompartmentPrivate((compartment))->sandboxConfig

static void
SetCompartmentPrincipal(JSCompartment *compartment, nsIPrincipal *principal)
{
  JS_SetCompartmentPrincipals(compartment, nsJSPrincipals::get(principal));
}


// Turn compartment into a Sandboxed compartment. If a sandbox is provided the
// compartment sandbox is set; otherwise sandbox-mode is enabled with the
// compartment label set to the public label.
NS_EXPORT_(void)
EnableCompartmentSandbox(JSCompartment *compartment,
                         mozilla::dom::Sandbox *sandbox)
{
  MOZ_ASSERT(compartment);

  if (IsCompartmentSandboxed(compartment))
    return;

  if (sandbox) {
    SANDBOX_CONFIG(compartment).SetSandbox(sandbox);

    // set empty privileges

    nsRefPtr<Label> privileges = new Label();
    MOZ_ASSERT(privileges);

    SANDBOX_CONFIG(compartment).SetPrivileges(privileges);
  } else { // sandbox-mode
    nsRefPtr<Label> privacy = new Label();
    MOZ_ASSERT(privacy);

    nsRefPtr<Label> trust = new Label();
    MOZ_ASSERT(trust);

    SANDBOX_CONFIG(compartment).SetPrivacyLabel(privacy);
    SANDBOX_CONFIG(compartment).SetTrustLabel(trust);

    // set privileges to compartment principal
    // we're not "copying" the principal since the principal may be a
    // null principal (iframe sandbox) and thus not a codebase principal
    nsCOMPtr<nsIPrincipal> privPrin = GetCompartmentPrincipal(compartment);
    nsRefPtr<Role> privRole = new Role(privPrin);
    ErrorResult aRv;
    nsRefPtr<Label> privileges = new Label(*privRole, aRv);
    MOZ_ASSERT(privileges);
    SANDBOX_CONFIG(compartment).SetPrivileges(privileges);
  }
}

NS_EXPORT_(bool)
IsCompartmentSandboxed(JSCompartment *compartment)
{
  MOZ_ASSERT(compartment);
  return SANDBOX_CONFIG(compartment).Enabled();
}

NS_EXPORT_(bool)
IsCompartmentSandbox(JSCompartment *compartment)
{
  MOZ_ASSERT(compartment);
  return SANDBOX_CONFIG(compartment).isSandbox();
}

NS_EXPORT_(bool)
IsCompartmentSandboxMode(JSCompartment *compartment)
{
  MOZ_ASSERT(compartment);
  return SANDBOX_CONFIG(compartment).isSandboxMode();
}

// This function adjusts the "security permieter".
// Specifically, it adjusts:
// 1. The CSP policy to restrict with whom the current compartment may
// network-communicate with.
// 2. The compartment principal to restrict writing to storage
// cnannels.
//
NS_EXPORT_(void)
RefineCompartmentSandboxPolicies(JSCompartment *compartment, JSContext *cx)
{

  // In sandbox, no need to adjust underlying principal/policy
  // Only adjust sandbox-mode compartments
  bool isSandbox = IsCompartmentSandbox(compartment);

  nsresult rv;

  // Clone the privacy label and reduce it:
  nsRefPtr<Label> privacy;
  {
    ErrorResult aRv;
    nsRefPtr<Label> originalPrivacy =
      SANDBOX_CONFIG(compartment).GetPrivacyLabel();
    privacy = originalPrivacy->Clone(aRv);
    MOZ_ASSERT(!aRv.Failed());
  }
  nsRefPtr<Label> privs = GetCompartmentPrivileges(compartment);
  privacy->Reduce(*privs);

  // Case 1: Empty/public label, don't loosen/impose new restrictions
  if (privacy->IsEmpty())
    return;

  nsString policy;
  PrincipalArray* labelPrincipals = privacy->GetPrincipalsIfSingleton();

  if (labelPrincipals && labelPrincipals->Length() > 0) {
    // Case 2: singleton disjunctive role 
    // Allow network access to all the origins in the list (and in the
    // privileges), but disable storage access since we can't
    // communicate with content origin.

    // Create list of origins
    nsString origins;
    for (unsigned i = 0; i < labelPrincipals->Length(); ++i) {
      char *origin = NULL;
      rv = labelPrincipals->ElementAt(i)->GetOrigin(&origin);
      MOZ_ASSERT(NS_SUCCEEDED(rv));
      AppendASCIItoUTF16(origin, origins);
      NS_Free(origin);
      origins.Append(NS_LITERAL_STRING(" "));
    }

    policy = NS_LITERAL_STRING("default-src ")  + origins
               + NS_LITERAL_STRING("'unsafe-inline'")
           + NS_LITERAL_STRING(";script-src ")  + origins
               + NS_LITERAL_STRING("'unsafe-inline'")
           + NS_LITERAL_STRING(";object-src ")  + origins
           + NS_LITERAL_STRING(";style-src ")   + origins
           + NS_LITERAL_STRING(";img-src ")     + origins
               + NS_LITERAL_STRING("'unsafe-inline'")
           + NS_LITERAL_STRING(";media-src ")   + origins
           + NS_LITERAL_STRING(";frame-src ")   + origins
           + NS_LITERAL_STRING(";font-src ")    + origins
           + NS_LITERAL_STRING(";connect-src ") + origins
           + NS_LITERAL_STRING(";");

  } else {
    // Case 3: not the empty label or singleton disjunctive role
    // Disable all network and storage access.

    // Policy to disable all communication
    policy = NS_LITERAL_STRING("default-src 'none' 'unsafe-inline';\
                                script-src  'none' 'unsafe-inline';\
                                object-src  'none';\
                                style-src   'none' 'unsafe-inline';\
                                img-src     'none';\
                                media-src   'none';\
                                frame-src   'none';\
                                font-src    'none';\
                                connect-src 'none';");
  }

  nsCOMPtr<nsIContentSecurityPolicy> csp;
  {
    nsCOMPtr<nsIPrincipal> compPrincipal = GetCompartmentPrincipal(compartment);
    MOZ_ASSERT(compPrincipal);

    // If CSP policy exists on current compartment, get it.
    // we handle composition of IFC with CSP by tightening down CSP
    rv = compPrincipal->GetCsp(getter_AddRefs(csp));
    MOZ_ASSERT(NS_SUCCEEDED(rv));
    // Create a new CSP object, if none exist
    if(!csp) {
      csp = do_CreateInstance("@mozilla.org/contentsecuritypolicy;1", &rv);
      MOZ_ASSERT(NS_SUCCEEDED(rv) && csp);
    }
  }

  if (!isSandbox) {
    // Create new principal to be used for document
    nsCOMPtr<nsIPrincipal> compPrincipal =
      do_CreateInstance("@mozilla.org/nullprincipal;1", &rv);
    MOZ_ASSERT (NS_SUCCEEDED(rv));

    // Set the compartment principal to this new principal
    SetCompartmentPrincipal(compartment, compPrincipal);

    // Get the principal URI
    nsCOMPtr<nsIURI> baseURI;
    rv = compPrincipal->GetURI(getter_AddRefs(baseURI));
    MOZ_ASSERT(NS_SUCCEEDED(rv));

    // Set the compartment location to the base URI
    EnsureCompartmentPrivate(compartment)->SetLocationURI(baseURI);

    // Get the compartment global
    nsCOMPtr<nsIGlobalObject> global =
      GetNativeForGlobal(JS_GetGlobalForCompartmentOrNull(cx, compartment));

    // Get the underlying window
    nsCOMPtr<nsIDOMWindow> win(do_QueryInterface(global));
    MOZ_ASSERT(win);

    // Get the window document
    nsCOMPtr<nsIDOMDocument> domDoc;
    win->GetDocument(getter_AddRefs(domDoc)); MOZ_ASSERT(domDoc);

    nsCOMPtr<nsIDocument> doc(do_QueryInterface(domDoc));
    MOZ_ASSERT(doc);

    // Set the document principal
    doc->SetPrincipal(compPrincipal);

    // Change the document base uri to the new base URI
    doc->SetBaseURI(baseURI);

    // Set iframe sandbox flags most restrcting flags:
    nsAttrValue sandboxAttr(nsGkAtoms::allowscripts);
    uint32_t flags = nsContentUtils::ParseSandboxAttributeToFlags(&sandboxAttr);
    doc->SetSandboxFlags(flags);

    csp->AppendPolicy(policy, baseURI, false, true);
    // set CSP  since we created a new principal
    rv = compPrincipal->SetCsp(csp);
    MOZ_ASSERT(NS_SUCCEEDED(rv));
  }

  // Refine policy of the csp object (may not be new)
  { // remove any existing policies
    // TODO: keep original -- from header -- CSP policies
    int numPolicies = 0;
    nsresult rv = csp->GetPolicyCount(&numPolicies);
    if (NS_SUCCEEDED(rv)) {
      for (int i=numPolicies-1; i>=0; i--)
        csp->RemovePolicy(i);
    }
  }

  if (cx)
    js::RecomputeWrappers(cx, js::AllCompartments(), js::AllCompartments());
}


#define DEFINE_SET_LABEL(name)                                    \
  NS_EXPORT_(void)                                                \
  SetCompartment##name(JSCompartment *compartment,                \
                      mozilla::dom::Label *aLabel)                \
  {                                                               \
    MOZ_ASSERT(compartment);                                      \
    MOZ_ASSERT(aLabel);                                           \
                                                                  \
    NS_ASSERTION(IsCompartmentSandboxed(compartment),             \
                 "Must call EnableCompartmentSandbox() first");   \
    if (!IsCompartmentSandboxed(compartment))                     \
      return;                                                     \
                                                                  \
    ErrorResult aRv;                                              \
    nsRefPtr<Label> label = (aLabel)->Clone(aRv);                 \
                                                                  \
    MOZ_ASSERT(!(aRv).Failed());                                  \
    SANDBOX_CONFIG(compartment).Set##name(label);                 \
  }

#define DEFINE_GET_LABEL(name)                                    \
  NS_EXPORT_(already_AddRefed<mozilla::dom::Label>)               \
  GetCompartment##name(JSCompartment *compartment)                \
  {                                                               \
    MOZ_ASSERT(compartment);                                      \
    MOZ_ASSERT(sandbox::IsCompartmentSandboxed(compartment));     \
    return SANDBOX_CONFIG(compartment).Get##name();               \
  }

// This function sets the compartment privacy label. It clones the given label.
// IMPORTANT: This function should not be exported to untrusted code.
// Untrusted code can only set the privacy label to a label that
// subsumes the "current label".
DEFINE_SET_LABEL(PrivacyLabel)
DEFINE_GET_LABEL(PrivacyLabel)

// This function sets the compartment trust label. It clones the given label.
// IMPORTANT: This function should not be exported to untrusted code.
// Untrusted code can only set the trust label to a label subsumed by
// the "current label".
DEFINE_SET_LABEL(TrustLabel)
DEFINE_GET_LABEL(TrustLabel)

// This function sets the compartment privacy clearance. It clones the given
// label.
// IMPORTANT: This function should not be exported to untrusted code.
// Untrusted code can only set the privacy clearance to a label that subsumes
// the privacy label.
DEFINE_SET_LABEL(PrivacyClearance)
DEFINE_GET_LABEL(PrivacyClearance)

// This function sets the compartment trust clearance. It clones the given
// label.
// IMPORTANT: This function should not be exported to untrusted code.
// Untrusted code can only set the trust clearance to a label subsumed by the
// trust label.
DEFINE_SET_LABEL(TrustClearance)
DEFINE_GET_LABEL(TrustClearance)


#undef DEFINE_SET_LABEL
#undef DEFINE_GET_LABEL

// This function gets a copy of the compartment privileges.
NS_EXPORT_(already_AddRefed<mozilla::dom::Label>)
GetCompartmentPrivileges(JSCompartment*compartment)
{
  ErrorResult aRv;

  nsRefPtr<Label> privs;
  
  if (sandbox::IsCompartmentSandboxed(compartment)) {
    privs = SANDBOX_CONFIG(compartment).GetPrivileges();
    privs = privs->Clone(aRv);
  }

  if (!privs || aRv.Failed())
    privs = new Label(); // empty privileges

  return privs.forget();
}

NS_EXPORT_(mozilla::dom::Sandbox*)
GetCompartmentSandbox(JSCompartment *compartment)
{
  MOZ_ASSERT(compartment);
  MOZ_ASSERT(sandbox::IsCompartmentSandboxed(compartment));
  return SANDBOX_CONFIG(compartment).GetSandbox();
}

// Check if information can flow from the compartment to an object labeled with
// |privacy| and |trust| into the compartment.
NS_EXPORT_(bool)
GuardWrite(JSCompartment *compartment,
          mozilla::dom::Label &privacy, mozilla::dom::Label &trust,
          mozilla::dom::Label *aPrivs)
{
  ErrorResult aRv;


  if (!sandbox::IsCompartmentSandboxed(compartment)) {
    NS_WARNING("Not in sandboxed compartment!\n");
    return false;
  }

  nsRefPtr<Label> privs = aPrivs ? aPrivs : new Label();
  nsRefPtr<mozilla::dom::Label> compPrivacy, compTrust;
  compPrivacy = xpc::sandbox::GetCompartmentPrivacyLabel(compartment);
  compTrust   = xpc::sandbox::GetCompartmentTrustLabel(compartment);

  // If any of the labels are missing, don't allow the information flow
  if (!compPrivacy || !compTrust) {
    NS_WARNING("Missing labels!\n");
    return false;
  }


#if 1
  {
    nsAutoString compPrivacyStr, compTrustStr, privacyStr, trustStr, privsStr;
    compPrivacy->Stringify(compPrivacyStr);
    compTrust->Stringify(compTrustStr);
    privacy.Stringify(privacyStr);
    trust.Stringify(trustStr);
    privs->Stringify(privsStr);

    printf("GuardWrite <%s,%s> to <%s,%s> | %s\n",
           NS_ConvertUTF16toUTF8(compPrivacyStr).get(),
           NS_ConvertUTF16toUTF8(compTrustStr).get(),
           NS_ConvertUTF16toUTF8(privacyStr).get(),
           NS_ConvertUTF16toUTF8(trustStr).get(),
           NS_ConvertUTF16toUTF8(privsStr).get());
  }
#endif


  // if not <compPrivacy,compTrust> [=_privs <privacy,trust>
  if (!(privacy.Subsumes(*privs, *compPrivacy) && compTrust->Subsumes(*privs, trust))) {
    NS_WARNING("Label not above current label!\n");
    return false;
  }

  // <privacy,trust> [=_privs  <clrPrivacy, clrTrust>

  nsRefPtr<mozilla::dom::Label> clrPrivacy, clrTrust;
  clrPrivacy = xpc::sandbox::GetCompartmentPrivacyClearance(compartment);
  clrTrust   = xpc::sandbox::GetCompartmentTrustClearance(compartment);

  bool sandboxMode = SANDBOX_CONFIG(compartment).isSandboxMode();

  // in sandbox-mode without clearance
  if (sandboxMode && !clrPrivacy && !clrTrust) {
    return true;
  }
  // <privacy,trust> [=_privs <clrPrivacy,clrTrust>
  if (clrPrivacy->Subsumes(*privs, privacy) && trust.Subsumes(*privs, *clrTrust)) {
    return true;
  } 

  NS_WARNING("Label above clearance!\n");
  return false;
}
// Check if compartment can write to dst
NS_EXPORT_(bool)
GuardWrite(JSCompartment *compartment, JSCompartment *dst)
{
#if 1
    {
        printf("GuardWrite :");
        {
            char *origin;
            uint32_t status = 0;
            GetCompartmentPrincipal(compartment)->GetOrigin(&origin);
            GetCompartmentPrincipal(compartment)->GetAppId(&status);
            printf(" %s [%x] to", origin, status); 
            nsMemory::Free(origin);
        }
        {
            char *origin;
            uint32_t status = 0;
            GetCompartmentPrincipal(dst)->GetOrigin(&origin);
            GetCompartmentPrincipal(dst)->GetAppId(&status);
            printf("%s [%x] \n", origin, status); 
            nsMemory::Free(origin);
        }
    }
#endif


  if (!sandbox::IsCompartmentSandboxed(dst)) {
    NS_WARNING("Destination compartmetn is not sandboxed!\n");
    return false;
  }
  nsRefPtr<Label> privacy = xpc::sandbox::GetCompartmentPrivacyLabel(dst);
  nsRefPtr<Label> trust   = xpc::sandbox::GetCompartmentTrustLabel(dst);
  nsRefPtr<Label> privs   = GetCompartmentPrivileges(compartment);

  if (!privacy || !trust || !privs) {
    NS_WARNING("Missing privacy or trust labels");
    return false;
  }

  return GuardWrite(compartment, *privacy, *trust, privs);
}
    
// Check if information can flow from an object labeled with |privacy|
// and |trust| into the compartment. For this to hold, the compartment
// must preserve privacy, i.e., the compartment privacy label must
// subsume the object privacy labe, and not be corrupted, i.e., the
// object trust label must be at least as trustworthy as the
// compartment trust label.
NS_EXPORT_(bool)
GuardRead(JSCompartment *compartment,
          mozilla::dom::Label &privacy, mozilla::dom::Label &trust,
          mozilla::dom::Label *aPrivs,
          JSContext *cx,
          bool doTaint)
{
  ErrorResult aRv;

  nsRefPtr<Label> privs = aPrivs ? aPrivs : new Label();
  nsRefPtr<mozilla::dom::Label> compPrivacy, compTrust;

  if (sandbox::IsCompartmentSandboxed(compartment)) {
    compPrivacy = xpc::sandbox::GetCompartmentPrivacyLabel(compartment);
    compTrust   = xpc::sandbox::GetCompartmentTrustLabel(compartment);
  } else {
    // compartment is not sandboxed
    nsCOMPtr<nsIPrincipal> privPrin = GetCompartmentPrincipal(compartment);
    nsRefPtr<Role> privRole = new Role(privPrin);
    compPrivacy = new Label(*privRole, aRv);
    compTrust   = new Label();
    if (aRv.Failed()) return false;
    // don't touch the compartment
    doTaint = false;
  }

  // If any of the labels are missing, don't allow the information flow
  if (!compPrivacy || !compTrust) {
    NS_WARNING("Missing labels!\n");
    return false;
  }


#if 1
  {
    nsAutoString compPrivacyStr, compTrustStr, privacyStr, trustStr, privsStr;
    compPrivacy->Stringify(compPrivacyStr);
    compTrust->Stringify(compTrustStr);
    privacy.Stringify(privacyStr);
    trust.Stringify(trustStr);
    privs->Stringify(privsStr);

    printf("GuardRead <%s,%s> to <%s,%s> | %s\n",
           NS_ConvertUTF16toUTF8(privacyStr).get(),
           NS_ConvertUTF16toUTF8(trustStr).get(),
           NS_ConvertUTF16toUTF8(compPrivacyStr).get(),
           NS_ConvertUTF16toUTF8(compTrustStr).get(),
           NS_ConvertUTF16toUTF8(privsStr).get());
  }
#endif


  // <privacy,trust> [=_privs <compPrivacy,compTrust>
  if (compPrivacy->Subsumes(*privs, privacy) && 
      trust.Subsumes(*privs, *compTrust))
    return true;

  // Compartment cannot directly read data, see if we can taint be to
  // allow it to read.

  if (doTaint) {
    nsRefPtr<mozilla::dom::Label> clrPrivacy =
      xpc::sandbox::GetCompartmentPrivacyClearance(compartment);
    nsRefPtr<mozilla::dom::Label> clrTrust   =
      xpc::sandbox::GetCompartmentTrustClearance(compartment);

    bool sandboxMode = SANDBOX_CONFIG(compartment).isSandboxMode();

    if ((sandboxMode && !clrPrivacy && !clrTrust) || 
        // in sandbox-mode without clearance
        (clrPrivacy->Subsumes(*privs,privacy) && 
         trust.Subsumes(*privs, *clrTrust)))
      // <privacy,trust> [=_privs <clrPrivacy,clrTrust>
    {
      // Label of object is not above clearance (if clearance is set),
      // so raise compartment label to allow the read.

      // join privacy
      compPrivacy->_And(privacy, aRv); 
      NS_ASSERTION(!aRv.Failed(), "internal _And clone failed.");
      if (aRv.Failed()) return false;
      //TODO: compPrivacy->Reduce(*privs);

      // join trust
      compTrust->_Or(trust, aRv);
      NS_ASSERTION(!aRv.Failed(), "internal _Or clone failed.");
      if (aRv.Failed()) return false;
      //TODO: compTrust->Reduce(*privs);

      RefineCompartmentSandboxPolicies(compartment, cx);

      return true;
    } 
  }

  NS_WARNING("Does not subsume, taint not allowed!\n");
  return false;
}

// Check if information can flow from compartment |source| to
// compartment |compartment|. If reading from a sandbox, the sandbox
// label is used; otherwise the current compartment label is used.
// For this to be safe we must not allow a compartment to read the
// label of a non-sandbox, i.e., sandbox-mode, compartment.
NS_EXPORT_(bool)
GuardRead(JSCompartment *compartment, JSCompartment *source, bool isGET)
{
  //isGET = true:  compartment is reading from source
  //               use compartment privs
  //isGET = false: source is writing to compartment
  //               use source privs
#if 1
    {
        printf("GuardRead %s :", isGET ? "GET" : "SET");
        {
            char *origin;
            uint32_t status = 0;
            GetCompartmentPrincipal(source)->GetOrigin(&origin);
            GetCompartmentPrincipal(source)->GetAppId(&status);
            printf("%s [%x]", origin, status); 
            nsMemory::Free(origin);
        }
        {
            char *origin;
            uint32_t status = 0;
            GetCompartmentPrincipal(compartment)->GetOrigin(&origin);
            GetCompartmentPrincipal(compartment)->GetAppId(&status);
            printf(" to %s [%x]\n", origin, status); 
            nsMemory::Free(origin);
        }
    }
#endif



  nsRefPtr<Label> privacy, trust;

  if (sandbox::IsCompartmentSandboxed(source)) {
    privacy = xpc::sandbox::GetCompartmentPrivacyLabel(source);
    trust   = xpc::sandbox::GetCompartmentTrustLabel(source);
  } else {
    privacy = new Label();
    trust   = new Label();
  }
  nsRefPtr<Label> privs = isGET ? GetCompartmentPrivileges(compartment) 
                                : GetCompartmentPrivileges(source);

  if (!privacy || !trust || !privs) {
    NS_WARNING("Missing privacy or trust labels");
    return false;
  }

  return GuardRead(compartment, *privacy, *trust, privs);
}

#undef SANDBOX_CONFIG

}; // sandbox
}; // xpc
