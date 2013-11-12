{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE RankNTypes    #-}
{-# LANGUAGE TupleSections #-}

module Network.HTTP.Conduit.OAuth.Util (
  view, over, set, iso, from, prism, preview, to, _Just, _Nothing
  ) where

import           Control.Applicative
import           Data.Functor.Constant
import           Data.Functor.Contravariant
import           Data.Functor.Identity
import           Data.Monoid
import           Data.Profunctor
import           Data.Profunctor.Unsafe
import           Unsafe.Coerce


-- mu Lens
--------------------------------------------------------------------------------

view :: ((a -> Constant a a) -> s -> Constant a s) -> s -> a
view inj = getConstant . inj Constant
{-# INLINE view #-}

over :: Profunctor p => (p a (Identity b) -> p s (Identity t)) -> p a b -> p s t
over inj f = runIdentity #. inj (Identity #. f)
{-# INLINE over #-}

set :: ((a -> Identity b) -> s -> Identity t) -> b -> s -> t
set l = over l . const
{-# INLINE set #-}

iso :: Profunctor p => (s -> a) -> (b -> t) -> p a b -> p s t
iso = dimap
{-# INLINE iso #-}

type AnIso s t a b = X a b a (Identity b) -> X a b s (Identity t)

withIso :: AnIso s t a b -> ((s -> a) -> (b -> t) -> r) -> r
withIso ai k = case ai (X id Identity) of
  X sa bt -> k sa (runIdentity #. bt)
{-# INLINE withIso #-}

from :: Profunctor p => AnIso s t a b -> p t s -> p b a
from l = withIso l $ \ sa bt -> iso bt sa
{-# INLINE from #-}

data X a b s t = X (s -> a) (b -> t) deriving ( Functor )

instance Profunctor (X a b) where
  dimap f g (X sa bt) = X (sa . f) (g . bt)
  {-# INLINE dimap #-}
  lmap f (X sa bt) = X (sa . f) bt
  {-# INLINE lmap #-}
  rmap f (X sa bt) = X sa (f . bt)
  {-# INLINE rmap #-}
  ( #. ) _ = unsafeCoerce
  {-# INLINE ( #. ) #-}
  ( .# ) p _ = unsafeCoerce p
  {-# INLINE ( .# ) #-}

prism ::
  (Choice p, Applicative f) =>
  (b -> t) -> (s -> Either t a) -> p a (f b) -> p s (f t)
prism bt seta = dimap seta (either pure (fmap bt)) . right'
{-# INLINE prism #-}

foldMapOf
  :: (Profunctor p, Profunctor p1) =>
     (p1 a2 (Constant b a3) -> p a (Constant c a1)) -> p1 a2 b -> p a c
foldMapOf l f = getConstant #. l (Constant #. f)
{-# INLINE foldMapOf #-}

preview :: ((a -> Constant (First a) a) -> s -> Constant (First a) s) -> s -> Maybe a
preview l = getFirst #. foldMapOf l (First #. Just)
{-# INLINE preview #-}

data Void = Void Void

absurd :: Void -> a
absurd (Void v) = absurd v
{-# INLINE absurd #-}

coerce :: (Contravariant f, Functor f) => f a -> f b
coerce a = absurd <$> contramap absurd a
{-# INLINE coerce #-}

to :: (Functor f, Contravariant f, Profunctor p) =>
      (s -> a) -> p a (f x) -> p s (f y)
to k = dimap k coerce
{-# INLINE to #-}

_Just :: (Applicative f, Choice p) =>
         p a (f b) -> p (Maybe a) (f (Maybe b))
_Just = prism Just (maybe (Left Nothing) Right)
{-# INLINE _Just #-}

_Nothing :: (Applicative f, Choice p) =>
            p () (f b) -> p (Maybe a1) (f (Maybe a))
_Nothing = prism (const Nothing) $ maybe (Right ()) (const $ Left Nothing)
{-# INLINE _Nothing #-}

_1 :: Functor f => (t -> f a) -> (t, t1) -> f (a, t1)
_1 inj (a, b) = (,b) <$> inj a
