//===- IndexBody.cpp - Indexing statements --------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "IndexingContext.h"
#include "clang/AST/RecursiveASTVisitor.h"

using namespace clang;
using namespace clang::index;

namespace {

class BodyIndexer : public RecursiveASTVisitor<BodyIndexer> {
  IndexingContext &IndexCtx;
  const NamedDecl *Parent;
  const DeclContext *ParentDC;
  SmallVector<Stmt*, 16> StmtStack;

  typedef RecursiveASTVisitor<BodyIndexer> base;
public:
  BodyIndexer(IndexingContext &indexCtx,
              const NamedDecl *Parent, const DeclContext *DC)
    : IndexCtx(indexCtx), Parent(Parent), ParentDC(DC) { }
  
  bool shouldWalkTypesOfTypeLocs() const { return false; }

  bool dataTraverseStmtPre(Stmt *S) {
    StmtStack.push_back(S);
    return true;
  }

  bool dataTraverseStmtPost(Stmt *S) {
    assert(StmtStack.back() == S);
    StmtStack.pop_back();
    return true;
  }

  bool TraverseTypeLoc(TypeLoc TL) {
    IndexCtx.indexTypeLoc(TL, Parent, ParentDC);
    return true;
  }

  bool TraverseNestedNameSpecifierLoc(NestedNameSpecifierLoc NNS) {
    IndexCtx.indexNestedNameSpecifierLoc(NNS, Parent, ParentDC);
    return true;
  }

  SymbolRoleSet getRolesForRef(const Expr *E,
                               SmallVectorImpl<SymbolRelation> &Relations) {
    SymbolRoleSet Roles{};
    assert(!StmtStack.empty() && E == StmtStack.back());
    if (StmtStack.size() == 1)
      return Roles;
    auto It = StmtStack.end()-2;
    while (isa<CastExpr>(*It) || isa<ParenExpr>(*It)) {
      if (auto ICE = dyn_cast<ImplicitCastExpr>(*It)) {
        if (ICE->getCastKind() == CK_LValueToRValue)
          Roles |= (unsigned)(unsigned)SymbolRole::Read;
      }
      if (It == StmtStack.begin())
        break;
      --It;
    }
    const Stmt *Parent = *It;

    if (auto BO = dyn_cast<BinaryOperator>(Parent)) {
      if (BO->getOpcode() == BO_Assign && BO->getLHS()->IgnoreParenCasts() == E)
        Roles |= (unsigned)SymbolRole::Write;

    } else if (auto UO = dyn_cast<UnaryOperator>(Parent)) {
      if (UO->isIncrementDecrementOp()) {
        Roles |= (unsigned)SymbolRole::Read;
        Roles |= (unsigned)SymbolRole::Write;
      } else if (UO->getOpcode() == UO_AddrOf) {
        Roles |= (unsigned)SymbolRole::AddressOf;
      }

    } else if (auto CA = dyn_cast<CompoundAssignOperator>(Parent)) {
      if (CA->getLHS()->IgnoreParenCasts() == E) {
        Roles |= (unsigned)SymbolRole::Read;
        Roles |= (unsigned)SymbolRole::Write;
      }

    } else if (auto CE = dyn_cast<CallExpr>(Parent)) {
      if (CE->getCallee()->IgnoreParenCasts() == E) {
        addCallRole(Roles, Relations);
        if (auto *ME = dyn_cast<MemberExpr>(E)) {
          if (auto *CXXMD = dyn_cast_or_null<CXXMethodDecl>(ME->getMemberDecl()))
            if (CXXMD->isVirtual() && !ME->hasQualifier()) {
              Roles |= (unsigned)SymbolRole::Dynamic;
              auto BaseTy = ME->getBase()->IgnoreImpCasts()->getType();
              if (!BaseTy.isNull())
                if (auto *CXXRD = BaseTy->getPointeeCXXRecordDecl())
                  Relations.emplace_back((unsigned)SymbolRole::RelationReceivedBy,
                                         CXXRD);
            }
        }
      } else if (auto CXXOp = dyn_cast<CXXOperatorCallExpr>(CE)) {
        if (CXXOp->getNumArgs() > 0 && CXXOp->getArg(0)->IgnoreParenCasts() == E) {
          OverloadedOperatorKind Op = CXXOp->getOperator();
          if (Op == OO_Equal) {
            Roles |= (unsigned)SymbolRole::Write;
          } else if ((Op >= OO_PlusEqual && Op <= OO_PipeEqual) ||
                     Op == OO_LessLessEqual || Op == OO_GreaterGreaterEqual ||
                     Op == OO_PlusPlus || Op == OO_MinusMinus) {
            Roles |= (unsigned)SymbolRole::Read;
            Roles |= (unsigned)SymbolRole::Write;
          } else if (Op == OO_Amp) {
            Roles |= (unsigned)SymbolRole::AddressOf;
          }
        }
      }
    }

    return Roles;
  }

  void addCallRole(SymbolRoleSet &Roles,
                   SmallVectorImpl<SymbolRelation> &Relations) {
    Roles |= (unsigned)SymbolRole::Call;
    if (auto *FD = dyn_cast<FunctionDecl>(ParentDC))
      Relations.emplace_back((unsigned)SymbolRole::RelationCalledBy, FD);
    else if (auto *MD = dyn_cast<ObjCMethodDecl>(ParentDC))
      Relations.emplace_back((unsigned)SymbolRole::RelationCalledBy, MD);
  }

  bool VisitDeclRefExpr(DeclRefExpr *E) {
    SmallVector<SymbolRelation, 4> Relations;
    SymbolRoleSet Roles = getRolesForRef(E, Relations);
    return IndexCtx.handleReference(E->getDecl(), E->getLocation(),
                                    Parent, ParentDC, Roles, Relations, E);
  }

  bool VisitMemberExpr(MemberExpr *E) {
    SourceLocation Loc = E->getMemberLoc();
    if (Loc.isInvalid())
      Loc = E->getLocStart();
    SmallVector<SymbolRelation, 4> Relations;
    SymbolRoleSet Roles = getRolesForRef(E, Relations);
    return IndexCtx.handleReference(E->getMemberDecl(), Loc,
                                    Parent, ParentDC, Roles, Relations, E);
  }

  bool VisitDesignatedInitExpr(DesignatedInitExpr *E) {
    for (DesignatedInitExpr::Designator &D : llvm::reverse(E->designators())) {
      if (D.isFieldDesignator())
        return IndexCtx.handleReference(D.getField(), D.getFieldLoc(), Parent,
                                        ParentDC, SymbolRoleSet(), {}, E);
    }
    return true;
  }

  bool VisitObjCIvarRefExpr(ObjCIvarRefExpr *E) {
    SmallVector<SymbolRelation, 4> Relations;
    SymbolRoleSet Roles = getRolesForRef(E, Relations);
    return IndexCtx.handleReference(E->getDecl(), E->getLocation(),
                                    Parent, ParentDC, Roles, Relations, E);
  }

  bool VisitObjCMessageExpr(ObjCMessageExpr *E) {
    auto isDynamic = [](const ObjCMessageExpr *MsgE)->bool {
      if (MsgE->getReceiverKind() != ObjCMessageExpr::Instance)
        return false;
      if (auto *RecE = dyn_cast<ObjCMessageExpr>(
              MsgE->getInstanceReceiver()->IgnoreParenCasts())) {
        if (RecE->getMethodFamily() == OMF_alloc)
          return false;
      }
      return true;
    };

    if (ObjCMethodDecl *MD = E->getMethodDecl()) {
      SymbolRoleSet Roles{};
      SmallVector<SymbolRelation, 2> Relations;
      addCallRole(Roles, Relations);
      if (E->isImplicit())
        Roles |= (unsigned)SymbolRole::Implicit;

      if (isDynamic(E)) {
        Roles |= (unsigned)SymbolRole::Dynamic;
        if (auto *RecD = E->getReceiverInterface())
          Relations.emplace_back((unsigned)SymbolRole::RelationReceivedBy, RecD);
      }

      return IndexCtx.handleReference(MD, E->getSelectorStartLoc(),
                                      Parent, ParentDC, Roles, Relations, E);
    }
    return true;
  }

  bool VisitObjCPropertyRefExpr(ObjCPropertyRefExpr *E) {
    if (E->isExplicitProperty())
      return IndexCtx.handleReference(E->getExplicitProperty(), E->getLocation(),
                                      Parent, ParentDC, SymbolRoleSet(), {}, E);

    // No need to do a handleReference for the objc method, because there will
    // be a message expr as part of PseudoObjectExpr.
    return true;
  }

  bool VisitMSPropertyRefExpr(MSPropertyRefExpr *E) {
    return IndexCtx.handleReference(E->getPropertyDecl(), E->getMemberLoc(),
                                    Parent, ParentDC, SymbolRoleSet(), {}, E);
  }

  bool VisitObjCProtocolExpr(ObjCProtocolExpr *E) {
    return IndexCtx.handleReference(E->getProtocol(), E->getProtocolIdLoc(),
                                    Parent, ParentDC, SymbolRoleSet(), {}, E);
  }

  bool passObjCLiteralMethodCall(const ObjCMethodDecl *MD, const Expr *E) {
    SymbolRoleSet Roles{};
    SmallVector<SymbolRelation, 2> Relations;
    addCallRole(Roles, Relations);
    Roles |= (unsigned)SymbolRole::Implicit;
    return IndexCtx.handleReference(MD, E->getLocStart(),
                                    Parent, ParentDC, Roles, Relations, E);
  }

  bool VisitObjCBoxedExpr(ObjCBoxedExpr *E) {
    if (ObjCMethodDecl *MD = E->getBoxingMethod()) {
      return passObjCLiteralMethodCall(MD, E);
    }
    return true;
  }
  
  bool VisitObjCDictionaryLiteral(ObjCDictionaryLiteral *E) {
    if (ObjCMethodDecl *MD = E->getDictWithObjectsMethod()) {
      return passObjCLiteralMethodCall(MD, E);
    }
    return true;
  }

  bool VisitObjCArrayLiteral(ObjCArrayLiteral *E) {
    if (ObjCMethodDecl *MD = E->getArrayWithObjectsMethod()) {
      return passObjCLiteralMethodCall(MD, E);
    }
    return true;
  }

  bool VisitCXXConstructExpr(CXXConstructExpr *E) {
    SymbolRoleSet Roles{};
    SmallVector<SymbolRelation, 2> Relations;
    addCallRole(Roles, Relations);
    return IndexCtx.handleReference(E->getConstructor(), E->getLocation(),
                                    Parent, ParentDC, Roles, Relations, E);
  }

  bool TraverseCXXOperatorCallExpr(CXXOperatorCallExpr *E,
                                   DataRecursionQueue *Q = nullptr) {
    if (E->getOperatorLoc().isInvalid())
      return true; // implicit.
    return base::TraverseCXXOperatorCallExpr(E, Q);
  }

  bool VisitDeclStmt(DeclStmt *S) {
    if (IndexCtx.shouldIndexFunctionLocalSymbols()) {
      IndexCtx.indexDeclGroupRef(S->getDeclGroup());
      return true;
    }

    DeclGroupRef DG = S->getDeclGroup();
    for (DeclGroupRef::iterator I = DG.begin(), E = DG.end(); I != E; ++I) {
      const Decl *D = *I;
      if (!D)
        continue;
      if (!IndexCtx.isFunctionLocalDecl(D))
        IndexCtx.indexTopLevelDecl(D);
    }

    return true;
  }

  bool TraverseLambdaCapture(LambdaExpr *LE, const LambdaCapture *C) {
    if (C->capturesThis() || C->capturesVLAType())
      return true;

    if (C->capturesVariable() && IndexCtx.shouldIndexFunctionLocalSymbols())
      return IndexCtx.handleReference(C->getCapturedVar(), C->getLocation(),
                                      Parent, ParentDC, SymbolRoleSet());

    // FIXME: Lambda init-captures.
    return true;
  }

  // RecursiveASTVisitor visits both syntactic and semantic forms, duplicating
  // the things that we visit. Make sure to only visit the semantic form.
  // Also visit things that are in the syntactic form but not the semantic one,
  // for example the indices in DesignatedInitExprs.
  bool TraverseInitListExpr(InitListExpr *S, DataRecursionQueue *Q = nullptr) {

    class SyntacticFormIndexer :
              public RecursiveASTVisitor<SyntacticFormIndexer> {
      IndexingContext &IndexCtx;
      const NamedDecl *Parent;
      const DeclContext *ParentDC;

    public:
      SyntacticFormIndexer(IndexingContext &indexCtx,
                            const NamedDecl *Parent, const DeclContext *DC)
        : IndexCtx(indexCtx), Parent(Parent), ParentDC(DC) { }

      bool shouldWalkTypesOfTypeLocs() const { return false; }

      bool VisitDesignatedInitExpr(DesignatedInitExpr *E) {
        for (DesignatedInitExpr::Designator &D : llvm::reverse(E->designators())) {
          if (D.isFieldDesignator())
            return IndexCtx.handleReference(D.getField(), D.getFieldLoc(),
                                            Parent, ParentDC, SymbolRoleSet(),
                                            {}, E);
        }
        return true;
      }
    };

    auto visitForm = [&](InitListExpr *Form) {
      for (Stmt *SubStmt : Form->children()) {
        if (!TraverseStmt(SubStmt, Q))
          return false;
      }
      return true;
    };

    InitListExpr *SemaForm = S->isSemanticForm() ? S : S->getSemanticForm();
    InitListExpr *SyntaxForm = S->isSemanticForm() ? S->getSyntacticForm() : S;

    if (SemaForm) {
      // Visit things present in syntactic form but not the semantic form.
      if (SyntaxForm) {
        SyntacticFormIndexer(IndexCtx, Parent, ParentDC).TraverseStmt(SyntaxForm);
      }
      return visitForm(SemaForm);
    }

    // No semantic, try the syntactic.
    if (SyntaxForm) {
      return visitForm(SyntaxForm);
    }

    return true;
  }
};

} // anonymous namespace

void IndexingContext::indexBody(const Stmt *S, const NamedDecl *Parent,
                                const DeclContext *DC) {
  if (!S)
    return;

  if (!DC)
    DC = Parent->getLexicalDeclContext();
  BodyIndexer(*this, Parent, DC).TraverseStmt(const_cast<Stmt*>(S));
}
