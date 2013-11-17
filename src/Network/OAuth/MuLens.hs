{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RankNTypes            #-}

-- |
-- Module      : Network.OAuth.MuLens
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
--
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
--
-- Tiny, @Control.Lens@ compatibility layer.

module Network.OAuth.MuLens (
  -- * Basics
  Lens, Traversal, Prism, Iso, view, use, preview, set,
  -- * Generalizations
  over, foldMapOf,
  -- * Building
  lens, iso, prism,
  -- * Tools
  zoom,
  -- * Convenience
  (<&>), (&), (^.), (.~), (%~), (<~)
  ) where

import           Control.Applicative
import           Control.Monad.Reader
import           Control.Monad.State
import           Data.Functor.Constant
import           Data.Functor.Identity
import           Data.Monoid
import           Data.Profunctor
import           Data.Profunctor.Unsafe

type Lens  s t a b = forall f   . (Functor f)               => (a -> f b) -> s -> f t
type Prism s t a b = forall p f . (Choice p, Applicative f) => p a (f b)  -> p s (f t)
type Iso   s t a b = forall p f . (Profunctor p, Functor f) => p a (f b)  -> p s (f t)
type Traversal s t a b = forall f   . (Applicative f)       => (a -> f b) -> s -> f t

view :: MonadReader s m => ((a -> Constant a a) -> s -> Constant a s) -> m a
view inj = asks (foldMapOf inj id)
{-# INLINE view #-}

use  :: MonadState s m => ((a -> Constant a a) -> s -> Constant a s) -> m a
use inj = foldMapOf inj id `liftM` get
{-# INLINE use #-}

preview :: ((a -> Constant (First a) a) -> s -> Constant (First a) s) -> s -> Maybe a
preview l = getFirst #. foldMapOf l (First #. Just)
{-# INLINE preview #-}

over :: Profunctor p => (p a (Identity b) -> p s (Identity t)) -> p a b -> p s t
over inj f = runIdentity #. inj (Identity #. f)
{-# INLINE over #-}

set :: ((a -> Identity b) -> s -> Identity t) -> b -> s -> t
set l = over l . const
{-# INLINE set #-}

foldMapOf :: ((a -> Constant r b) -> s -> Constant r t) -> (a -> r) -> s -> r
foldMapOf inj f = getConstant . inj (Constant . f)
{-# INLINE foldMapOf #-}

zoom :: Monad m => Lens s s t t -> StateT t m a -> StateT s m a
zoom l m = do
  t <- use l
  (a, t') <- lift $ runStateT m t
  modify (l .~ t')
  return a

lens :: (s -> a) -> (s -> b -> t) -> Lens s t a b
lens gt st inj x = st x <$> inj (gt x)
{-# INLINE lens #-}

iso :: Profunctor p => (s -> a) -> (b -> t) -> p a b -> p s t
iso = dimap
{-# INLINE iso #-}

prism ::
  (Choice p, Applicative f) =>
  (b -> t) -> (s -> Either t a) -> p a (f b) -> p s (f t)
prism bt seta = dimap seta (either pure (fmap bt)) . right'
{-# INLINE prism #-}

infixl 5 <&>
(<&>) :: Functor f => f a -> (a -> b) -> f b
(<&>) = flip (<$>)
{-# INLINE (<&>) #-}

infixl 1 &
(&) :: b -> (b -> c) -> c
(&) = flip ($)
{-# INLINE (&) #-}

infixl 8 ^.
(^.) ::  s -> ((a -> Constant a a) -> s -> Constant a s) -> a
(^.) = flip view
{-# INLINE (^.) #-}

infixr 4 .~
(.~) :: ((a -> Identity b) -> s -> Identity t) -> b -> s -> t
(.~) = set
{-# INLINE (.~) #-}

infixr 4 %~
(%~) :: ((a -> Identity b) -> s -> Identity t) -> (a -> b) -> s -> t
(%~) = over
{-# INLINE (%~) #-}

infixr 2 <~
(<~) :: MonadState s m => ((a -> Identity b) -> s -> Identity s) -> m b -> m ()
l <~ m = do { a <- m; modify (l .~ a) }
